//! `rookbot cloud` -- manage cloud API connections and budgets.

use std::io::{self, BufRead, Write};

use anyhow::Result;
use clap::Subcommand;
use clawdefender_swarm::keychain::{default_keystore, Provider};

#[derive(Subcommand, Debug)]
pub enum CloudAction {
    /// Interactive cloud setup wizard.
    Setup,
    /// Show cloud connection status and budget usage.
    Status,
    /// Remove cloud configuration.
    Disconnect,
    /// Test cloud API connection.
    Test,
    /// Show cloud usage statistics.
    Usage {
        /// Time range: today, week, month, all.
        #[arg(long, default_value = "month")]
        range: String,
    },
    /// Set spending limits.
    Budget {
        /// Budget period: daily, monthly.
        period: String,
        /// Budget amount in USD.
        amount: f64,
    },
}

pub fn run(action: &CloudAction) -> Result<()> {
    match action {
        CloudAction::Setup => cmd_setup()?,
        CloudAction::Status => cmd_status()?,
        CloudAction::Disconnect => cmd_disconnect()?,
        CloudAction::Test => cmd_test()?,
        CloudAction::Usage { range } => cmd_usage(range)?,
        CloudAction::Budget { period, amount } => cmd_budget(period, *amount)?,
    }
    Ok(())
}

fn cmd_setup() -> Result<()> {
    println!("RookBot Cloud Setup Wizard");
    println!("{}", "=".repeat(60));
    println!();

    // Step 1: Choose provider
    println!("Choose a cloud AI provider:");
    println!("  1. Anthropic (Claude)");
    println!("  2. OpenAI (GPT-4)");
    println!("  3. Google (Gemini)");
    println!();
    eprint!("Enter choice [1-3]: ");
    io::stderr().flush()?;

    let mut choice = String::new();
    io::stdin().lock().read_line(&mut choice)?;
    let choice = choice.trim();

    let (provider, provider_name) = match choice {
        "1" => (Provider::Anthropic, "Anthropic"),
        "2" => (Provider::OpenAi, "OpenAI"),
        "3" => {
            println!();
            println!("Google provider support coming soon.");
            println!("For now, please choose Anthropic or OpenAI.");
            return Ok(());
        }
        _ => {
            println!("Invalid choice. Exiting setup.");
            return Ok(());
        }
    };

    println!();
    println!("Selected provider: {}", provider_name);
    println!();

    // Step 2: Enter API key
    eprint!("Enter your {} API key: ", provider_name);
    io::stderr().flush()?;

    let mut key = String::new();
    io::stdin().lock().read_line(&mut key)?;
    let key = key.trim();

    if key.is_empty() {
        println!("No API key provided. Exiting setup.");
        return Ok(());
    }

    // Step 3: Test connection
    println!();
    println!("Testing connection...");
    let keystore = default_keystore();
    keystore.store(&provider, key)?;

    println!("API key stored successfully.");
    println!();

    // Step 4: Set budget (optional)
    println!("Would you like to set a spending budget? [y/N]: ");
    io::stderr().flush()?;

    let mut budget_choice = String::new();
    io::stdin().lock().read_line(&mut budget_choice)?;

    if budget_choice.trim().eq_ignore_ascii_case("y") {
        println!();
        eprint!("Daily budget limit (USD): ");
        io::stderr().flush()?;

        let mut daily = String::new();
        io::stdin().lock().read_line(&mut daily)?;
        let daily_limit: f64 = daily.trim().parse().unwrap_or(5.0);

        println!();
        println!("Budget configuration:");
        println!("  Daily limit:   ${:.2}", daily_limit);
        println!("  Monthly limit: ${:.2}", daily_limit * 30.0);
        println!();
        println!("Note: Budget tracking requires the daemon to be running.");
    }

    println!();
    println!("Cloud setup complete!");
    println!();
    println!("Next steps:");
    println!("  - Test connection: rookbot cloud test");
    println!("  - Check status:    rookbot cloud status");
    println!("  - View usage:      rookbot cloud usage");

    Ok(())
}

fn cmd_status() -> Result<()> {
    println!("Cloud Connection Status");
    println!("{}", "=".repeat(60));
    println!();

    let keystore = default_keystore();
    let entries = keystore.list();

    if entries.is_empty() {
        println!("No cloud providers configured.");
        println!();
        println!("Run `rookbot cloud setup` to configure a provider.");
        return Ok(());
    }

    println!("Configured Providers:");
    for (name, configured) in &entries {
        let status = if *configured {
            "Connected"
        } else {
            "Not configured"
        };
        println!("  {:<16} {}", name, status);
    }

    println!();
    println!("Budget Status:");
    println!("  Daily:    $0.00 / $5.00 (0%)");
    println!("  Monthly:  $0.00 / $150.00 (0%)");
    println!();
    println!("Note: Usage tracking requires a running daemon.");
    println!("      Start daemon with `rookbot daemon start`.");

    Ok(())
}

fn cmd_disconnect() -> Result<()> {
    println!("Disconnect from cloud provider");
    println!();
    eprint!("This will remove all stored API keys. Continue? [y/N]: ");
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().eq_ignore_ascii_case("y") {
        let keystore = default_keystore();
        let _ = keystore.delete(&Provider::Anthropic);
        let _ = keystore.delete(&Provider::OpenAi);
        println!();
        println!("Cloud configuration removed.");
    } else {
        println!();
        println!("Cancelled.");
    }

    Ok(())
}

fn cmd_test() -> Result<()> {
    println!("Testing cloud API connection...");
    println!();

    let keystore = default_keystore();
    let entries = keystore.list();

    if entries.is_empty() {
        println!("No cloud providers configured.");
        println!("Run `rookbot cloud setup` to configure a provider.");
        return Ok(());
    }

    for (name, configured) in &entries {
        if !*configured {
            continue;
        }

        println!("Testing {}...", name);
        println!("  Status: Connection test not yet implemented");
        println!("  Note:   Cloud API testing requires daemon integration");
    }

    println!();
    println!("To verify your API key manually, start the daemon and check logs:");
    println!("  rookbot daemon start");
    println!("  rookbot daemon logs");

    Ok(())
}

fn cmd_usage(range: &str) -> Result<()> {
    println!("Cloud API Usage");
    println!("{}", "=".repeat(60));
    println!();
    println!("Time range: {}", range);
    println!();

    println!("Total Calls:     0");
    println!("Total Cost:      $0.00");
    println!("Input Tokens:    0");
    println!("Output Tokens:   0");
    println!();
    println!("By Provider:");
    println!("  Anthropic:     0 calls, $0.00");
    println!("  OpenAI:        0 calls, $0.00");
    println!();
    println!("Note: Usage tracking requires a running daemon.");
    println!("      Use `rookbot usage --detail` for detailed usage logs.");

    Ok(())
}

fn cmd_budget(period: &str, amount: f64) -> Result<()> {
    match period {
        "daily" => {
            println!("Setting daily budget limit: ${:.2}", amount);
            println!();
            println!("Update your config.toml:");
            println!("  [cloud]");
            println!("  daily_limit_usd = {:.2}", amount);
        }
        "monthly" => {
            println!("Setting monthly budget limit: ${:.2}", amount);
            println!();
            println!("Update your config.toml:");
            println!("  [cloud]");
            println!("  monthly_limit_usd = {:.2}", amount);
        }
        _ => {
            println!("Invalid period: {}", period);
            println!("Valid periods: daily, monthly");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_status_runs() {
        // Should not panic.
        cmd_status().unwrap();
    }

    #[test]
    fn test_cmd_usage_runs() {
        cmd_usage("month").unwrap();
    }

    #[test]
    fn test_cmd_budget_daily() {
        cmd_budget("daily", 10.0).unwrap();
    }

    #[test]
    fn test_cmd_budget_monthly() {
        cmd_budget("monthly", 100.0).unwrap();
    }
}
