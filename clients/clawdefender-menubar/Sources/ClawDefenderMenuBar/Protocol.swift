import Foundation

// MARK: - Daemon -> UI

enum UiRequest: Decodable {
    case PromptUser(event_summary: String, rule_name: String, options: [String])
    case Alert(severity: Severity, message: String, event_id: String)
    case StatusUpdate(blocked_count: UInt64, allowed_count: UInt64, prompted_count: UInt64, uptime_secs: UInt64)
    case SwarmEnrichment(prompt_id: String, risk_level: String, explanation: String, recommended_action: String, specialist_summaries: [String])
    case SlmEnrichment(prompt_id: String, risk_level: String, explanation: String, confidence: Float)

    private enum CodingKeys: String, CodingKey {
        case PromptUser, Alert, StatusUpdate, SwarmEnrichment, SlmEnrichment
    }

    private struct PromptUserPayload: Decodable {
        let event_summary: String
        let rule_name: String
        let options: [String]
    }

    private struct AlertPayload: Decodable {
        let severity: Severity
        let message: String
        let event_id: String
    }

    private struct StatusUpdatePayload: Decodable {
        let blocked_count: UInt64
        let allowed_count: UInt64
        let prompted_count: UInt64
        let uptime_secs: UInt64
    }

    private struct SwarmPayload: Decodable {
        let prompt_id: String
        let risk_level: String
        let explanation: String
        let recommended_action: String
        let specialist_summaries: [String]
    }

    private struct SlmPayload: Decodable {
        let prompt_id: String
        let risk_level: String
        let explanation: String
        let confidence: Float
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let p = try container.decodeIfPresent(PromptUserPayload.self, forKey: .PromptUser) {
            self = .PromptUser(event_summary: p.event_summary, rule_name: p.rule_name, options: p.options)
        } else if let a = try container.decodeIfPresent(AlertPayload.self, forKey: .Alert) {
            self = .Alert(severity: a.severity, message: a.message, event_id: a.event_id)
        } else if let s = try container.decodeIfPresent(StatusUpdatePayload.self, forKey: .StatusUpdate) {
            self = .StatusUpdate(blocked_count: s.blocked_count, allowed_count: s.allowed_count, prompted_count: s.prompted_count, uptime_secs: s.uptime_secs)
        } else if let sw = try container.decodeIfPresent(SwarmPayload.self, forKey: .SwarmEnrichment) {
            self = .SwarmEnrichment(prompt_id: sw.prompt_id, risk_level: sw.risk_level, explanation: sw.explanation, recommended_action: sw.recommended_action, specialist_summaries: sw.specialist_summaries)
        } else if let sl = try container.decodeIfPresent(SlmPayload.self, forKey: .SlmEnrichment) {
            self = .SlmEnrichment(prompt_id: sl.prompt_id, risk_level: sl.risk_level, explanation: sl.explanation, confidence: sl.confidence)
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "Unknown UiRequest variant"))
        }
    }
}

// MARK: - UI -> Daemon

enum UserDecision: String, Encodable {
    case AllowOnce
    case DenyOnce
    case AllowSession
    case DenySession
    case AddPolicyRule
}

enum UiResponse: Encodable {
    case Decision(event_id: String, action: UserDecision)
    case KillProcess(pid: UInt32)
    case Dismiss(event_id: String)

    private enum CodingKeys: String, CodingKey {
        case Decision, KillProcess, Dismiss
    }

    private struct DecisionPayload: Encodable {
        let event_id: String
        let action: UserDecision
    }

    private struct KillPayload: Encodable {
        let pid: UInt32
    }

    private struct DismissPayload: Encodable {
        let event_id: String
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .Decision(let eventId, let action):
            try container.encode(DecisionPayload(event_id: eventId, action: action), forKey: .Decision)
        case .KillProcess(let pid):
            try container.encode(KillPayload(pid: pid), forKey: .KillProcess)
        case .Dismiss(let eventId):
            try container.encode(DismissPayload(event_id: eventId), forKey: .Dismiss)
        }
    }
}

// MARK: - Severity

enum Severity: String, Decodable {
    case Info
    case Low
    case Medium
    case High
    case Critical
}
