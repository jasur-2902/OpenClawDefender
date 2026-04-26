import { useEffect } from "react";

/**
 * Hook that listens for the global Cmd+R refresh event
 * and invokes the provided callback to refresh page data.
 */
export function useRefreshShortcut(onRefresh: () => void) {
  useEffect(() => {
    function handleRefresh() {
      onRefresh();
    }

    window.addEventListener("rookbot:refresh", handleRefresh);
    return () => window.removeEventListener("rookbot:refresh", handleRefresh);
  }, [onRefresh]);
}
