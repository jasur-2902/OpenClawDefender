import Foundation

protocol DaemonConnectionDelegate: AnyObject {
    func daemonDidConnect()
    func daemonDidDisconnect()
    func daemonDidReceive(request: UiRequest)
}

final class DaemonConnection {
    weak var delegate: DaemonConnectionDelegate?

    private let socketPath: String
    private var fileHandle: FileHandle?
    private var socketFD: Int32 = -1
    private var readBuffer = Data()
    private var reconnectTimer: Timer?
    private let reconnectInterval: TimeInterval = 5.0
    private let queue = DispatchQueue(label: "com.clawdefender.daemon-connection")
    private(set) var isConnected = false

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        self.socketPath = "\(home)/.local/share/clawdefender/clawdefender.sock"
    }

    func connect() {
        queue.async { [weak self] in
            self?.connectInternal()
        }
    }

    func disconnect() {
        stopReconnectTimer()
        disconnectInternal()
    }

    func send(response: UiResponse) {
        queue.async { [weak self] in
            self?.sendInternal(response: response)
        }
    }

    // MARK: - Internal

    private func connectInternal() {
        guard !isConnected else { return }

        socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else {
            scheduleReconnect()
            return
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = socketPath.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            close(socketFD)
            socketFD = -1
            scheduleReconnect()
            return
        }

        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dest in
                for (i, byte) in pathBytes.enumerated() {
                    dest[i] = byte
                }
            }
        }

        let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Foundation.connect(socketFD, sockaddrPtr, addrLen)
            }
        }

        guard result == 0 else {
            close(socketFD)
            socketFD = -1
            scheduleReconnect()
            return
        }

        isConnected = true
        fileHandle = FileHandle(fileDescriptor: socketFD, closeOnDealloc: false)
        readBuffer = Data()

        DispatchQueue.main.async { [weak self] in
            self?.delegate?.daemonDidConnect()
        }

        startReading()
    }

    private func disconnectInternal() {
        guard isConnected else { return }
        isConnected = false
        fileHandle = nil
        if socketFD >= 0 {
            close(socketFD)
            socketFD = -1
        }
        DispatchQueue.main.async { [weak self] in
            self?.delegate?.daemonDidDisconnect()
        }
    }

    private func startReading() {
        queue.async { [weak self] in
            self?.readLoop()
        }
    }

    private func readLoop() {
        let bufferSize = 4096
        var buf = [UInt8](repeating: 0, count: bufferSize)

        while isConnected {
            let bytesRead = read(socketFD, &buf, bufferSize)
            if bytesRead <= 0 {
                disconnectInternal()
                scheduleReconnect()
                return
            }

            readBuffer.append(contentsOf: buf[0..<bytesRead])
            processLines()
        }
    }

    private func processLines() {
        while let newlineIndex = readBuffer.firstIndex(of: UInt8(ascii: "\n")) {
            let lineData = readBuffer[readBuffer.startIndex..<newlineIndex]
            readBuffer = Data(readBuffer[(newlineIndex + 1)...])

            guard !lineData.isEmpty else { continue }

            do {
                let request = try JSONDecoder().decode(UiRequest.self, from: Data(lineData))
                DispatchQueue.main.async { [weak self] in
                    self?.delegate?.daemonDidReceive(request: request)
                }
            } catch {
                NSLog("ClawDefender: failed to decode UiRequest: \(error)")
            }
        }
    }

    private func sendInternal(response: UiResponse) {
        guard isConnected, socketFD >= 0 else { return }

        do {
            var data = try JSONEncoder().encode(response)
            data.append(UInt8(ascii: "\n"))
            data.withUnsafeBytes { ptr in
                if let base = ptr.baseAddress {
                    _ = Foundation.write(socketFD, base, ptr.count)
                }
            }
        } catch {
            NSLog("ClawDefender: failed to encode UiResponse: \(error)")
        }
    }

    private func scheduleReconnect() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.stopReconnectTimer()
            self.reconnectTimer = Timer.scheduledTimer(withTimeInterval: self.reconnectInterval, repeats: false) { [weak self] _ in
                self?.connect()
            }
        }
    }

    private func stopReconnectTimer() {
        DispatchQueue.main.async { [weak self] in
            self?.reconnectTimer?.invalidate()
            self?.reconnectTimer = nil
        }
    }
}
