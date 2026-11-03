use aegis_cli::{
    exit_code, render_active_verify, render_browser_crawl, render_html_crawl,
    render_local_scan_report, render_openapi_import, render_report, render_rules_bundle_check,
    render_rules_feed_check, render_rules_feed_sign, render_rules_test, render_saved_scan_report,
    render_url_crawl, render_url_seed_import, run_crawl_browser_log_command,
    run_crawl_html_command, run_crawl_url_command, run_import_openapi_command,
    run_import_urls_command, run_local_scan_command, run_report_export_command,
    run_rules_bundle_check_command, run_rules_feed_check_command, run_rules_feed_sign_command,
    run_rules_test_command, run_scan_command, run_verify_active_command, Cli, Command,
    ReportSubcommand, RulesSubcommand,
};
use aegis_scanner::UreqHttpProbeClient;
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    let result: Result<(i32, String), aegis_cli::CliError> = match cli.command {
        Command::Scan(command) => {
            let client = UreqHttpProbeClient;
            run_scan_command(&command, &client).and_then(|report| {
                render_report(&report, command.format).map(|output| (exit_code(&report), output))
            })
        }
        Command::ScanLocal(command) => {
            let client = UreqHttpProbeClient;
            run_local_scan_command(&command, &client).and_then(|report| {
                render_local_scan_report(&report, command.format)
                    .map(|output| (exit_code_from_local_report(&report), output))
            })
        }
        Command::Report(command) => match command.command {
            ReportSubcommand::Export(command) => {
                run_report_export_command(&command).and_then(|report| {
                    render_saved_scan_report(&report, command.format).map(|output| (0, output))
                })
            }
        },
        Command::Rules(command) => match command.command {
            RulesSubcommand::Test(command) => run_rules_test_command(&command).and_then(|report| {
                render_rules_test(&report, command.format)
                    .map(|output| (exit_code_from_rules_report(&report), output))
            }),
            RulesSubcommand::FeedCheck(command) => {
                run_rules_feed_check_command(&command).and_then(|report| {
                    render_rules_feed_check(&report, command.format)
                        .map(|output| (exit_code_from_rules_feed_report(&report), output))
                })
            }
            RulesSubcommand::FeedSign(command) => {
                run_rules_feed_sign_command(&command).and_then(|report| {
                    render_rules_feed_sign(&report, command.format).map(|output| (0, output))
                })
            }
            RulesSubcommand::BundleCheck(command) => run_rules_bundle_check_command(&command)
                .and_then(|report| {
                    render_rules_bundle_check(&report, command.format)
                        .map(|output| (exit_code_from_rules_bundle_report(&report), output))
                }),
        },
        Command::ImportOpenapi(command) => {
            run_import_openapi_command(&command).and_then(|result| {
                render_openapi_import(&result, command.format).map(|output| (0, output))
            })
        }
        Command::ImportUrls(command) => run_import_urls_command(&command).and_then(|result| {
            render_url_seed_import(&result, command.format).map(|output| (0, output))
        }),
        Command::CrawlHtml(command) => run_crawl_html_command(&command).and_then(|result| {
            render_html_crawl(&result, command.format).map(|output| (0, output))
        }),
        Command::CrawlBrowserLog(command) => {
            run_crawl_browser_log_command(&command).and_then(|result| {
                render_browser_crawl(&result, command.format).map(|output| (0, output))
            })
        }
        Command::CrawlUrl(command) => {
            let client = UreqHttpProbeClient;
            run_crawl_url_command(&command, &client).and_then(|result| {
                render_url_crawl(&result, command.format).map(|output| (0, output))
            })
        }
        Command::VerifyActive(command) => {
            let client = UreqHttpProbeClient;
            run_verify_active_command(&command, &client).and_then(|report| {
                render_active_verify(&report, command.format)
                    .map(|output| (exit_code_from_active_report(&report), output))
            })
        }
    };

    match result {
        Ok((code, output)) => {
            println!("{output}");
            std::process::exit(code);
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn exit_code_from_active_report(report: &aegis_cli::CliActiveVerifyReport) -> i32 {
    if report.failed_policy {
        2
    } else {
        0
    }
}

fn exit_code_from_local_report(report: &aegis_cli::CliLocalScanReport) -> i32 {
    if report.failed_policy {
        2
    } else {
        0
    }
}

fn exit_code_from_rules_report(report: &aegis_cli::CliRulesTestReport) -> i32 {
    if report.passed {
        0
    } else {
        2
    }
}

fn exit_code_from_rules_feed_report(report: &aegis_cli::CliRulesFeedCheckReport) -> i32 {
    if report.passed {
        0
    } else {
        2
    }
}

fn exit_code_from_rules_bundle_report(report: &aegis_cli::CliRulesBundleCheckReport) -> i32 {
    if report.passed {
        0
    } else {
        2
    }
}
