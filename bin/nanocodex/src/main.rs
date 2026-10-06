// This build only connects to OpenAI hosts; the Tempo provider routes through
// third-party payment and inference hosts.
#[cfg(feature = "tempo")]
compile_error!("the `tempo` feature is not available in the OpenAI-only build");

mod auth;
mod browser;
mod computer;
mod config;
mod launcher;
mod mcp;
#[path = "mpp_disabled.rs"]
mod mpp;
mod observability;
mod run;
mod startup_timing;
mod subagents;
mod tui;
mod version;
#[cfg(any(
    all(target_os = "linux", not(target_env = "musl")),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod vm;
#[cfg(not(any(
    all(target_os = "linux", not(target_env = "musl")),
    all(target_os = "macos", target_arch = "aarch64")
)))]
#[path = "vm_unsupported.rs"]
mod vm;

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, builder::NonEmptyStringValueParser};
use eyre::{Result, WrapErr, eyre};
use nanocodex::agent::rollout::RolloutConfig;

use config::AgentArgs;
use observability::ObservabilityArgs;

#[derive(Parser)]
#[command(
    version = version::SHORT_VERSION,
    long_version = version::LONG_VERSION,
    about = "An interactive coding agent and headless JSONL runner",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    agent: AgentArgs,

    #[command(flatten)]
    observability: ObservabilityArgs,

    #[command(flatten)]
    vm: vm::VmArgs,

    /// Submit an initial prompt immediately after the TUI opens.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    prompt: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Discover and control a running interactive terminal.
    Tui(nanocodex_tui_control::Cli),
    /// Install or refresh the upstream computer-use runtime.
    Computer(computer::Computer),
    /// Manage `ChatGPT` subscription login.
    Auth(auth::Auth),
    /// Internal entrypoint for one dedicated libkrun VMM process.
    #[command(hide = true)]
    VmRunConfig(vm::VmRunConfig),
    /// Run one prompt and stream JSONL events to stdout.
    Run(Box<RunCommand>),
    /// Resume a Codex or Nanocodex thread in the interactive TUI.
    Resume(Box<ResumeCommand>),
}

#[derive(Args)]
struct RunCommand {
    #[command(flatten)]
    run: run::Run,

    #[command(flatten)]
    agent: AgentArgs,

    #[command(flatten)]
    observability: ObservabilityArgs,

    #[command(flatten)]
    vm: vm::VmArgs,
}

#[derive(Args)]
struct ResumeCommand {
    /// Codex thread UUID to resume. Omit it to select from discovered sessions.
    #[arg(value_parser = NonEmptyStringValueParser::new())]
    thread_id: Option<String>,

    #[command(flatten)]
    agent: AgentArgs,

    #[command(flatten)]
    observability: ObservabilityArgs,

    #[command(flatten)]
    vm: vm::VmArgs,

    /// Submit an initial follow-on prompt immediately after the TUI opens.
    #[arg(long, value_parser = NonEmptyStringValueParser::new())]
    prompt: Option<String>,
}

fn main() -> ExitCode {
    let _startup = startup_timing::Stage::new("process");
    match try_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            ExitCode::FAILURE
        }
    }
}

fn try_main() -> Result<()> {
    launcher::initialize_install_root();
    nanocodex::oai::transport::install_default_rustls_crypto_provider();
    // Keep direct `cargo run` behavior consistent with the Justfile without
    // requiring shell-specific syntax to load the repository's `.env` file.
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();
    if let Some(Command::VmRunConfig(command)) = &cli.command {
        return command.run();
    }
    run_with_runtime(run(cli))
}

fn run_with_runtime(future: impl std::future::Future<Output = Result<()>>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(future);
    // Application cleanup has completed. Optional MCP discovery can still own a
    // blocking DNS lookup, which Tokio cannot cancel. Foreground work and its
    // owned cleanup were awaited above; give no extra exit grace period to
    // these disposable background tasks.
    runtime.shutdown_background();
    result
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Tui(command)) => command.run().await.map_err(Into::into),
        Some(Command::Computer(command)) => command.run().await.map_err(|error| eyre!(error)),
        Some(Command::Auth(command)) => command.run().await,
        Some(Command::VmRunConfig(_)) => unreachable!("VMM commands run before Tokio starts"),
        Some(Command::Run(command)) => {
            let _observability = command.observability.install(false, command.agent.cwd())?;
            command.run.run(command.agent, command.vm).await
        }
        Some(Command::Resume(command)) => {
            let codex_home = config::default_codex_home()?;
            let rollouts = RolloutConfig::new(&codex_home);
            let thread_id = match command.thread_id {
                Some(thread_id) => thread_id,
                None => {
                    let sessions = rollouts.list_sessions().wrap_err_with(|| {
                        format!(
                            "failed to discover Codex threads under {}",
                            codex_home.display()
                        )
                    })?;
                    if sessions.is_empty() {
                        return Err(eyre!(
                            "no resumable Codex threads found under {}",
                            codex_home.display()
                        ));
                    }
                    let Some(thread_id) = tui::select_resume_session(&sessions)? else {
                        return Ok(());
                    };
                    thread_id
                }
            };
            let session = rollouts
                .load_session(&thread_id)
                .wrap_err_with(|| format!("failed to load Codex thread {thread_id}"))?;
            tui::run_observed(
                command.agent,
                command.vm,
                command.prompt.map(tui::InitialPrompt::plain),
                Some(session),
                Some(command.observability),
            )
            .await
        }
        None => {
            tui::run_observed(
                cli.agent,
                cli.vm,
                cli.prompt.map(tui::InitialPrompt::plain),
                None,
                Some(cli.observability),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_waits_for_foreground_cleanup_before_success_or_error() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        for fails in [false, true] {
            let cleaned = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&cleaned);
            let result = run_with_runtime(async move {
                // The application future owns and awaits this cleanup, even on
                // its error path. Runtime background shutdown must follow it.
                let cleanup = tokio::spawn(async move {
                    tokio::task::yield_now().await;
                    observed.store(true, Ordering::SeqCst);
                });
                cleanup.await.unwrap();
                if fails {
                    Err(eyre!("synthetic runtime failure"))
                } else {
                    Ok(())
                }
            });
            assert!(cleaned.load(Ordering::SeqCst));
            assert_eq!(result.is_err(), fails);
        }
    }

    #[test]
    fn runtime_shutdown_does_not_wait_for_background_blocking_work() {
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };

        for fails in [false, true] {
            let (release, blocked) = mpsc::channel();
            let (finished, completion) = mpsc::channel();
            let started = Instant::now();
            let result = run_with_runtime(async move {
                let (ready, received) = tokio::sync::oneshot::channel();
                drop(tokio::task::spawn_blocking(move || {
                    let _ = ready.send(());
                    let _ = blocked.recv_timeout(Duration::from_secs(5));
                    let _ = finished.send(());
                }));
                received.await.unwrap();
                if fails {
                    Err(eyre!("synthetic runtime failure"))
                } else {
                    Ok(())
                }
            });
            let elapsed = started.elapsed();
            // Release our synthetic blocking task even if the timing assertion fails.
            let _ = release.send(());
            completion.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(
                elapsed < Duration::from_secs(1),
                "shutdown took {elapsed:?}"
            );
            assert_eq!(result.is_err(), fails);
        }
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn tempo_flag_selects_the_tui_transport() {
        let cli = Cli::try_parse_from([
            "nanocodex",
            "--provider.tempo",
            "--provider.tempo.wallet-store",
            "/tmp/tempo-wallet.json",
        ])
        .unwrap();

        assert!(cli.command.is_none());
        assert!(cli.agent.uses_tempo());
        assert_eq!(
            cli.agent.responses_transport(),
            nanocodex::oai::transport::ResponsesTransport::Https
        );
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn tempo_flag_selects_the_one_shot_transport() {
        let cli = Cli::try_parse_from([
            "nanocodex",
            "run",
            "reply with ok",
            "--provider.tempo",
            "--provider.tempo.wallet-store",
            "/tmp/tempo-wallet.json",
        ])
        .unwrap();

        let Some(Command::Run(command)) = cli.command else {
            unreachable!();
        };
        assert!(command.agent.uses_tempo());
        assert_eq!(
            command.agent.responses_transport(),
            nanocodex::oai::transport::ResponsesTransport::Https
        );
    }

    #[test]
    fn openai_provider_is_explicitly_selectable() {
        let cli = Cli::try_parse_from(["nanocodex", "--provider.openai", "--api-key", "test-key"])
            .unwrap();

        assert!(!cli.agent.uses_tempo());
        assert_eq!(
            cli.agent.responses_transport(),
            nanocodex::oai::transport::ResponsesTransport::WebSocket
        );
    }

    #[test]
    fn local_durability_testing_has_explicit_identity_and_store() {
        let cli = Cli::try_parse_from([
            "nanocodex",
            "run",
            "durable turn",
            "--local-durability",
            "/tmp/nanocodex-durability.sqlite",
            "--local-durability-state-id",
            "hammer-root",
            "--request-id",
            "turn-1",
            "--rollouts",
            "false",
        ])
        .unwrap();

        let Some(Command::Run(command)) = cli.command else {
            panic!("run command was not parsed");
        };
        assert!(command.run.uses_local_durability());

        let error = Cli::try_parse_from([
            "nanocodex",
            "run",
            "durable turn",
            "--local-durability-state-id",
            "orphaned-state",
        ])
        .err()
        .unwrap();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn vm_tools_are_opt_in_for_tui_and_one_shot_runs() {
        let tui = Cli::try_parse_from(["nanocodex"]).unwrap();
        assert!(!tui.vm.is_enabled());

        let tui = Cli::try_parse_from([
            "nanocodex",
            "--vm",
            "/tmp/rootfs",
            "--vm-workspace",
            "/workspace",
        ])
        .unwrap();
        assert!(tui.vm.is_enabled());

        let run = Cli::try_parse_from(["nanocodex", "run", "reply with ok", "--vm", "/tmp/rootfs"])
            .unwrap();
        let Some(Command::Run(run)) = run.command else {
            panic!("run command was not parsed");
        };
        assert!(run.vm.is_enabled());
    }

    #[test]
    fn browser_and_cookie_selection_follow_platform_defaults() {
        let tui = Cli::try_parse_from(["nanocodex"]).unwrap();
        assert!(tui.agent.browser_enabled());
        assert!(tui.agent.uses_persistent_browser_profile());
        assert!(!tui.agent.copies_all_browser_cookies());
        #[cfg(target_os = "macos")]
        assert!(!tui.agent.uses_brave_browser());
        #[cfg(target_os = "macos")]
        assert!(tui.agent.uses_interactive_browser_cookie_authorization());

        let tui = Cli::try_parse_from(["nanocodex", "--browser"]).unwrap();
        assert!(tui.agent.browser_enabled());
        assert!(!tui.agent.uses_brave_browser());

        let brave = Cli::try_parse_from(["nanocodex", "--browser=brave"]).unwrap();
        assert!(brave.agent.browser_enabled());
        assert!(brave.agent.uses_brave_browser());

        let chromium = Cli::try_parse_from(["nanocodex", "--browser=chromium"]).unwrap();
        assert!(chromium.agent.browser_enabled());
        assert!(!chromium.agent.uses_brave_browser());

        let interactive = Cli::try_parse_from(["nanocodex", "--cookie-auth=interactive"]).unwrap();
        assert!(
            interactive
                .agent
                .uses_interactive_browser_cookie_authorization()
        );

        let host_passkeys = Cli::try_parse_from(["nanocodex", "--passkeys=host"]).unwrap();
        assert!(host_passkeys.agent.uses_host_browser_passkeys());

        let temporary = Cli::try_parse_from(["nanocodex", "--browser-profile=temporary"]).unwrap();
        assert!(!temporary.agent.uses_persistent_browser_profile());
        assert!(temporary.agent.copies_all_browser_cookies());

        assert!(Cli::try_parse_from(["nanocodex", "--cookies=none"]).is_err());
        assert!(Cli::try_parse_from(["nanocodex", "--cookies=brave"]).is_err());

        let run = Cli::try_parse_from(["nanocodex", "run", "inspect example.com"]).unwrap();
        let Some(Command::Run(run)) = run.command else {
            panic!("run command was not parsed");
        };
        assert!(run.agent.browser_enabled());

        let disabled = Cli::try_parse_from(["nanocodex", "--browser=none"]).unwrap();
        assert!(!disabled.agent.browser_enabled());
        assert!(!disabled.agent.copies_all_browser_cookies());
    }

    #[test]
    fn vm_tuning_requires_an_opted_in_rootfs() {
        let error = Cli::try_parse_from(["nanocodex", "--vm-cpus", "4"])
            .err()
            .unwrap();

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn provider_selection_is_exclusive() {
        let error = Cli::try_parse_from(["nanocodex", "--provider.openai", "--provider.tempo"])
            .err()
            .unwrap();

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[cfg(not(feature = "tempo"))]
    #[test]
    fn tempo_provider_is_absent_from_direct_agent_builds() {
        let error = Cli::try_parse_from(["nanocodex", "--provider.tempo"])
            .err()
            .unwrap();

        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn resume_accepts_a_thread_id_and_agent_configuration() {
        let cli = Cli::try_parse_from([
            "nanocodex",
            "resume",
            "019c0d31-c308-7d91-bff4-5dca82d15ac6",
            "--provider.openai",
            "--api-key",
            "test-key",
            "--prompt",
            "continue",
        ])
        .unwrap();

        let Some(Command::Resume(command)) = cli.command else {
            panic!("resume command was not parsed");
        };
        assert_eq!(
            command.thread_id.as_deref(),
            Some("019c0d31-c308-7d91-bff4-5dca82d15ac6")
        );
        assert_eq!(command.prompt.as_deref(), Some("continue"));
        assert!(!command.agent.uses_tempo());
    }

    #[test]
    fn resume_without_a_thread_id_opens_discovery_path() {
        let cli = Cli::try_parse_from(["nanocodex", "resume", "--provider.openai"])
            .expect("resume should accept an omitted thread UUID");

        let Some(Command::Resume(command)) = cli.command else {
            panic!("resume command was not parsed");
        };
        assert!(command.thread_id.is_none());
    }
}
