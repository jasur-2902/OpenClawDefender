use crate::state::ServerProfileSummary;

/// Behavioral context enrichment data.
#[derive(Debug, Clone)]
pub struct BehavioralContextData {
    pub frequency_description: String,
    pub profile_status: String,
    pub historical_count: u64,
    pub is_first_occurrence: bool,
    pub anomaly_score: f64,
}

/// Generate a human-readable behavioral context string from a server profile.
pub fn generate_behavioral_context(profile: Option<&ServerProfileSummary>) -> String {
    let profile = match profile {
        Some(p) => p,
        None => return "I do not have behavioral data for this tool yet.".to_string(),
    };

    if profile.status == "learning" {
        let events_needed = 100u64.saturating_sub(profile.total_calls);
        return format!(
            "I am still learning this server's patterns. {} more events until baseline.",
            events_needed
        );
    }

    if profile.anomaly_score >= 0.7 {
        return "This server's recent behavior has been unusual. I am watching it more closely."
            .to_string();
    }

    if profile.anomaly_score < 0.1 && profile.total_calls > 100 {
        return "This server's behavior has been completely consistent.".to_string();
    }

    if profile.total_calls < 5 {
        return format!(
            "This server has done this {} time(s) before.",
            profile.total_calls
        );
    }

    if profile.total_calls < 50 {
        return "This happens regularly.".to_string();
    }

    // High volume: estimate daily rate (assume ~7 days of data)
    let daily_rate = profile.total_calls / 7;
    format!("This is routine -- about {} times per day.", daily_rate)
}

/// Generate a behavioral context string using event-specific historical count.
pub fn generate_behavioral_context_with_count(
    profile: Option<&ServerProfileSummary>,
    historical_count: u64,
    is_first_occurrence: bool,
) -> String {
    let profile = match profile {
        Some(p) => p,
        None => return "I do not have behavioral data for this tool yet.".to_string(),
    };

    if profile.status == "learning" {
        let events_needed = 100u64.saturating_sub(profile.total_calls);
        return format!(
            "I am still learning this server's patterns. {} more events until baseline.",
            events_needed
        );
    }

    if is_first_occurrence && profile.status != "learning" {
        return "First time this server has done this.".to_string();
    }

    if profile.anomaly_score >= 0.7 {
        return "This server's recent behavior has been unusual. I am watching it more closely."
            .to_string();
    }

    if historical_count == 0 {
        return "This is new behavior for this server.".to_string();
    }

    if historical_count < 5 {
        return format!(
            "This server has done this {} time(s) before.",
            historical_count
        );
    }

    if historical_count < 50 {
        return "This happens regularly.".to_string();
    }

    if profile.anomaly_score < 0.1 && historical_count > 100 {
        return "This server's behavior has been completely consistent.".to_string();
    }

    let daily_rate = historical_count / 7;
    format!("This is routine -- about {} times per day.", daily_rate)
}

/// Map an anomaly score to a human-readable risk explanation.
pub fn risk_explanation_from_anomaly(anomaly_score: f64) -> String {
    if anomaly_score >= 0.9 {
        "Behavioral analysis shows a dangerous deviation from this server's learned baseline."
            .to_string()
    } else if anomaly_score >= 0.7 {
        "Behavioral analysis shows suspicious deviation from this server's learned baseline."
            .to_string()
    } else if anomaly_score >= 0.4 {
        "Behavioral analysis shows unusual deviation from this server's learned baseline."
            .to_string()
    } else {
        "Behavioral analysis shows this is within normal parameters.".to_string()
    }
}

/// Map an anomaly score to a threat level label.
pub fn threat_level_from_anomaly(anomaly_score: f64) -> &'static str {
    if anomaly_score >= 0.9 {
        "dangerous"
    } else if anomaly_score >= 0.7 {
        "suspicious"
    } else if anomaly_score >= 0.4 {
        "unusual"
    } else {
        "normal"
    }
}
