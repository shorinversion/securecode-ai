# Какой код нужен `securecode analyze`

Измерение, не удаление: список модулей, которых не касается продукт (прогон `analyze`,
сервер, воркер, остальные команды CLI). Их по-прежнему могут импортировать скрипты и
тесты. Решение об удалении принимает владелец отдельно.

## Как измерено

- `analyze`: реальный прогон `securecode analyze --provider local` в чистом процессе,
  множество загруженных модулей `securecode_ai.*` (форматы отчёта, Архитектор, трасса — как в
  обычном прогоне). Процессы сканеров (`spawn`) импортируют только уже загруженные модули.
- сервер и воркер, остальные команды CLI (`securecode_ai.cli`), скрипты (`scripts/`, `demo/`):
  статическое транзитивное замыкание импортов по исходникам (`ast`, включая импорты внутри
  функций); тесты учтены отдельной колонкой.
- покрытие: тесты stage unit `scripts/quality.py` (`tests/unit` и несколько интеграционных файлов), измерено модулей: 588

## Итог

| Группа | Модулей | Строк |
| --- | ---: | ---: |
| всего | 588 | 265785 |
| нужны `analyze` | 327 | 167989 |
| только сервер, воркер или другие команды CLI | 205 | 82636 |
| **не нужны продукту** | 56 | 15160 |
| из них нужны только скриптам и тестам (бенчмарки, оценка, релизные утилиты) | 56 | 15160 |
| из них нужны только тестам | 0 | 0 |
| из них не нужны никому | 0 | 0 |

## Кандидаты на удаление

| Модуль | Строк | Покрытие | Скрипты | Тесты |
| --- | ---: | ---: | :---: | :---: |
| `securecode_ai.adapters.local_repair_oci_broker` | 767 | 0% | да | да |
| `securecode_ai.adapters.local_repair_oci_child` | 687 | 0% | да | да |
| `securecode_ai.adapters.scm_artifacts` | 676 | 88% | да | да |
| `securecode_ai.core.promotion_decision` | 599 | 83% | да | да |
| `securecode_ai.adapters.public_core_execution` | 525 | 87% | да | да |
| `securecode_ai.adapters.product_conformance` | 509 | 87% | да | да |
| `securecode_ai.adapters.public_core_runner_primitives` | 502 | 80% | да | да |
| `securecode_ai.core.evaluation_lab` | 502 | 79% | да | да |
| `securecode_ai.core.escalation` | 462 | 85% | да | да |
| `securecode_ai.core.offline_optimization` | 462 | 82% | да | да |
| `securecode_ai.adapters.public_discovery_observation` | 455 | 84% | да | да |
| `securecode_ai.core.evaluation_authority` | 440 | 77% | да | да |
| `securecode_ai.core.convergence` | 405 | 71% | да | да |
| `securecode_ai.core.development_benchmark_aggregate` | 403 | 89% | да | да |
| `securecode_ai.core.release_benchmark` | 370 | 43% | да | да |
| `securecode_ai.adapters.local_repair_root_cause_oracle` | 353 | 29% | да | да |
| `securecode_ai.core.promotion_registry_store` | 323 | 52% | да | да |
| `securecode_ai.core.finding_validation` | 322 | 83% | да | да |
| `securecode_ai.adapters.public_core_fixtures` | 305 | 95% | да | да |
| `securecode_ai.core.development_benchmark_models` | 301 | 81% | да | да |
| `securecode_ai.adapters.github_summary` | 285 | 82% | да | да |
| `securecode_ai.core.investigation_telemetry` | 278 | 84% | да | да |
| `securecode_ai.core.synthetic_lineage` | 273 | 89% | да | да |
| `securecode_ai.core.evaluation_access` | 266 | 86% | да | да |
| `securecode_ai.core.evaluation_lab_models` | 266 | 91% | да | да |
| `securecode_ai.adapters.github_checks` | 264 | 90% | да | да |
| `securecode_ai.adapters.public_core_runner_runner` | 263 | 75% | да | да |
| `securecode_ai.core.evaluation_lab_evidence` | 260 | 95% | да | да |
| `securecode_ai.adapters.public_core_runner_composition` | 254 | 80% | да | да |
| `securecode_ai.core.optimization_promotion` | 254 | 82% | да | да |
| `securecode_ai.adapters.local_repair_oci_commands` | 246 | 0% | да | да |
| `securecode_ai.core.offline_optimization_authority` | 223 | 77% | да | да |
| `securecode_ai.core.synthetic_cases` | 210 | 84% | да | да |
| `securecode_ai.contracts.schema_export` | 209 | 79% | да | да |
| `securecode_ai.core.evaluation_candidate_store` | 195 | 84% | да | да |
| `securecode_ai.core.ablation_study` | 175 | 75% | да | да |
| `securecode_ai.core.synthetic_oracle` | 175 | 83% | да | да |
| `securecode_ai.core.performance_budget` | 174 | 47% | да | да |
| `securecode_ai.core.code_index` | 156 | 49% | да | да |
| `securecode_ai.core.optimization_candidates` | 156 | 91% | да | да |
| `securecode_ai.core.validation_promotion` | 138 | 89% | да | да |
| `securecode_ai.core.performance_regression` | 123 | 25% | да | да |
| `securecode_ai.core.promotion_registry` | 119 | 83% | да | да |
| `securecode_ai.adapters.public_core_runner` | 96 | 100% | да | да |
| `securecode_ai.core.rlm_experiment` | 94 | 89% | да | да |
| `securecode_ai.core.ablation_metrics` | 84 | 51% | да | да |
| `securecode_ai.adapters.public_core_runner_loader` | 82 | 92% | да | да |
| `securecode_ai.core.release_metrics` | 77 | 100% | да | да |
| `securecode_ai.adapters.local_repair_security_scan` | 74 | 95% | да | да |
| `securecode_ai.adapters.remote_provider_budget_config` | 69 | 28% | да | да |
| `securecode_ai.adapters.local_model_qualification_record` | 66 | 24% | да | да |
| `securecode_ai.core.offline_optimization_evidence` | 48 | 100% | да | да |
| `securecode_ai.adapters.local_model_qualification` | 46 | 100% | да | да |
| `securecode_ai.core.development_benchmark_math` | 41 | 63% | да | да |
| `securecode_ai.adapters.gitlab_http_api` | 30 | 100% | да | да |
| `securecode_ai.core.development_benchmark` | 23 | 100% | да | да |

## Все модули

| Модуль | Строк | analyze | сервер/воркер | CLI | скрипты | тесты | Покрытие |
| --- | ---: | :---: | :---: | :---: | :---: | :---: | ---: |
| `securecode_ai.adapters` | 285 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.adapter_runtime_execution` | 509 | да | да | да | да | да | 92% |
| `securecode_ai.adapters.adapter_runtime_helpers` | 167 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.adapter_runtime_state` | 39 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.config` | 572 | да | да | да | да | да | 96% |
| `securecode_ai.adapters.coverage_causes` | 105 | да | нет | да | да | да | 100% |
| `securecode_ai.adapters.cst` | 68 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.cst_ecmascript` | 311 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.cst_go` | 204 | да | да | да | да | да | 79% |
| `securecode_ai.adapters.cst_models` | 106 | да | да | да | да | да | 87% |
| `securecode_ai.adapters.cst_python` | 224 | да | да | да | да | да | 95% |
| `securecode_ai.adapters.cwe89` | 590 | да | да | да | да | да | 83% |
| `securecode_ai.adapters.cwe89_contracts` | 222 | да | да | да | да | да | 92% |
| `securecode_ai.adapters.cwe89_multilanguage` | 45 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.cwe89_multilanguage_models` | 196 | да | да | да | да | да | 86% |
| `securecode_ai.adapters.cwe89_multilanguage_scanner` | 432 | да | да | да | да | да | 77% |
| `securecode_ai.adapters.cwe89_multilanguage_utilities` | 233 | да | да | да | да | да | 98% |
| `securecode_ai.adapters.cwe_portfolio` | 61 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.cwe_portfolio_helpers` | 889 | да | да | да | да | да | 83% |
| `securecode_ai.adapters.cwe_portfolio_models` | 363 | да | да | да | да | да | 83% |
| `securecode_ai.adapters.dependency_scanning` | 595 | да | да | да | да | да | 80% |
| `securecode_ai.adapters.dependency_scanning_go` | 264 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.dependency_scanning_javascript` | 298 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.dependency_scanning_javascript_locks` | 703 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.dependency_scanning_manifests` | 635 | да | да | да | да | да | 14% |
| `securecode_ai.adapters.dependency_scanning_osv` | 364 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.dependency_scanning_precedence` | 442 | да | да | да | да | да | 14% |
| `securecode_ai.adapters.dependency_scanning_setup_py` | 192 | да | да | да | да | да | 13% |
| `securecode_ai.adapters.dependency_scanning_yarn` | 276 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.ecmascript_cwe117` | 1056 | да | да | да | да | да | 38% |
| `securecode_ai.adapters.ecmascript_cwe1321` | 979 | да | да | да | да | да | 36% |
| `securecode_ai.adapters.ecmascript_cwe1333` | 1435 | да | да | да | да | да | 27% |
| `securecode_ai.adapters.ecmascript_cwe209` | 1240 | да | да | да | да | да | 63% |
| `securecode_ai.adapters.ecmascript_cwe22` | 1089 | да | да | да | да | да | 40% |
| `securecode_ai.adapters.ecmascript_cwe295` | 845 | да | да | да | да | да | 34% |
| `securecode_ai.adapters.ecmascript_cwe306` | 1301 | да | да | да | да | да | 48% |
| `securecode_ai.adapters.ecmascript_cwe307` | 1120 | да | да | да | да | да | 56% |
| `securecode_ai.adapters.ecmascript_cwe338` | 930 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.ecmascript_cwe352` | 622 | да | да | да | да | да | 41% |
| `securecode_ai.adapters.ecmascript_cwe367` | 1188 | да | да | да | да | да | 41% |
| `securecode_ai.adapters.ecmascript_cwe377` | 1013 | да | да | да | да | да | 36% |
| `securecode_ai.adapters.ecmascript_cwe400` | 1214 | да | да | да | да | да | 35% |
| `securecode_ai.adapters.ecmascript_cwe476` | 1119 | да | да | да | да | да | 38% |
| `securecode_ai.adapters.ecmascript_cwe502` | 805 | да | да | да | да | да | 45% |
| `securecode_ai.adapters.ecmascript_cwe521` | 1034 | да | да | да | да | да | 62% |
| `securecode_ai.adapters.ecmascript_cwe532` | 1386 | да | да | да | да | да | 34% |
| `securecode_ai.adapters.ecmascript_cwe601` | 1111 | да | да | да | да | да | 37% |
| `securecode_ai.adapters.ecmascript_cwe611` | 1280 | да | да | да | да | да | 32% |
| `securecode_ai.adapters.ecmascript_cwe613` | 1305 | да | да | да | да | да | 31% |
| `securecode_ai.adapters.ecmascript_cwe614` | 1054 | да | да | да | да | да | 40% |
| `securecode_ai.adapters.ecmascript_cwe639` | 1071 | да | да | да | да | да | 39% |
| `securecode_ai.adapters.ecmascript_cwe732` | 1055 | да | да | да | да | да | 32% |
| `securecode_ai.adapters.ecmascript_cwe776` | 1043 | да | да | да | да | да | 39% |
| `securecode_ai.adapters.ecmascript_cwe78` | 1050 | да | да | да | да | да | 35% |
| `securecode_ai.adapters.ecmascript_cwe79` | 1050 | да | да | да | да | да | 40% |
| `securecode_ai.adapters.ecmascript_cwe798` | 863 | да | да | да | да | да | 50% |
| `securecode_ai.adapters.ecmascript_cwe862` | 864 | да | да | да | да | да | 71% |
| `securecode_ai.adapters.ecmascript_cwe90` | 1085 | да | да | да | да | да | 34% |
| `securecode_ai.adapters.ecmascript_cwe918` | 1135 | да | да | да | да | да | 46% |
| `securecode_ai.adapters.ecmascript_cwe94` | 748 | да | да | да | да | да | 45% |
| `securecode_ai.adapters.endpoint` | 369 | да | да | да | да | да | 87% |
| `securecode_ai.adapters.git_snapshot` | 283 | да | да | да | да | да | 81% |
| `securecode_ai.adapters.git_trust` | 87 | да | да | да | да | да | 76% |
| `securecode_ai.adapters.github_annotations` | 282 | нет | да | нет | да | да | 83% |
| `securecode_ai.adapters.github_api` | 230 | нет | да | да | да | да | 64% |
| `securecode_ai.adapters.github_app` | 482 | нет | да | нет | да | да | 77% |
| `securecode_ai.adapters.github_checks` | 264 | нет | нет | нет | да | да | 90% |
| `securecode_ai.adapters.github_comments` | 615 | нет | да | нет | да | да | 64% |
| `securecode_ai.adapters.github_publish` | 368 | нет | нет | да | да | да | 93% |
| `securecode_ai.adapters.github_sarif` | 704 | нет | да | нет | да | да | 18% |
| `securecode_ai.adapters.github_summary` | 285 | нет | нет | нет | да | да | 82% |
| `securecode_ai.adapters.github_writer` | 282 | нет | да | нет | да | да | 95% |
| `securecode_ai.adapters.gitlab_api` | 827 | нет | да | нет | да | да | 55% |
| `securecode_ai.adapters.gitlab_api_responses` | 146 | нет | да | нет | да | да | 75% |
| `securecode_ai.adapters.gitlab_ci` | 521 | нет | да | нет | да | да | 96% |
| `securecode_ai.adapters.gitlab_discussions` | 290 | нет | да | нет | да | да | 97% |
| `securecode_ai.adapters.gitlab_http_api` | 30 | нет | нет | нет | да | да | 100% |
| `securecode_ai.adapters.gitlab_summary` | 317 | нет | да | нет | да | да | 85% |
| `securecode_ai.adapters.gitlab_writer` | 573 | нет | да | нет | да | да | 68% |
| `securecode_ai.adapters.go_cwe117` | 833 | да | да | да | да | да | 34% |
| `securecode_ai.adapters.go_cwe1333` | 577 | да | да | да | да | да | 67% |
| `securecode_ai.adapters.go_cwe209` | 915 | да | да | да | да | да | 40% |
| `securecode_ai.adapters.go_cwe22` | 711 | да | да | да | да | да | 38% |
| `securecode_ai.adapters.go_cwe295` | 764 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.go_cwe306` | 910 | да | да | да | да | да | 47% |
| `securecode_ai.adapters.go_cwe307` | 875 | да | да | да | да | да | 45% |
| `securecode_ai.adapters.go_cwe327` | 624 | да | да | да | да | да | 65% |
| `securecode_ai.adapters.go_cwe338` | 1081 | да | да | да | да | да | 53% |
| `securecode_ai.adapters.go_cwe352` | 993 | да | да | да | да | да | 32% |
| `securecode_ai.adapters.go_cwe367` | 825 | да | да | да | да | да | 43% |
| `securecode_ai.adapters.go_cwe400` | 989 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.go_cwe476` | 872 | да | да | да | да | да | 70% |
| `securecode_ai.adapters.go_cwe502` | 927 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.go_cwe521` | 782 | да | да | да | да | да | 45% |
| `securecode_ai.adapters.go_cwe532` | 1052 | да | да | да | да | да | 43% |
| `securecode_ai.adapters.go_cwe598` | 936 | да | да | да | да | да | 38% |
| `securecode_ai.adapters.go_cwe601` | 1039 | да | да | да | да | да | 39% |
| `securecode_ai.adapters.go_cwe613` | 988 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.go_cwe614` | 874 | да | да | да | да | да | 45% |
| `securecode_ai.adapters.go_cwe639` | 1018 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.go_cwe776` | 1091 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.go_cwe78` | 656 | да | да | да | да | да | 41% |
| `securecode_ai.adapters.go_cwe79` | 937 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.go_cwe798` | 873 | да | да | да | да | да | 47% |
| `securecode_ai.adapters.go_cwe862` | 986 | да | да | да | да | да | 55% |
| `securecode_ai.adapters.go_cwe90` | 862 | да | да | да | да | да | 41% |
| `securecode_ai.adapters.go_cwe918` | 731 | да | да | да | да | да | 55% |
| `securecode_ai.adapters.go_cwe_crypto` | 443 | да | да | да | да | да | 52% |
| `securecode_ai.adapters.local_durable_files` | 291 | да | да | да | да | да | 10% |
| `securecode_ai.adapters.local_model_qualification` | 46 | нет | нет | нет | да | да | 100% |
| `securecode_ai.adapters.local_model_qualification_models` | 569 | нет | да | да | да | да | 52% |
| `securecode_ai.adapters.local_model_qualification_record` | 66 | нет | нет | нет | да | да | 24% |
| `securecode_ai.adapters.local_model_qualification_validation` | 390 | нет | да | да | да | да | 22% |
| `securecode_ai.adapters.local_patch_status` | 372 | нет | да | да | да | да | 19% |
| `securecode_ai.adapters.local_patch_status_lock` | 161 | да | да | да | да | да | 17% |
| `securecode_ai.adapters.local_product_host` | 97 | да | да | да | да | да | 90% |
| `securecode_ai.adapters.local_product_host_git` | 111 | да | да | да | да | да | 70% |
| `securecode_ai.adapters.local_product_host_host` | 126 | да | да | да | да | да | 79% |
| `securecode_ai.adapters.local_product_host_linux` | 89 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.local_product_host_primitives` | 132 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.local_product_host_windows` | 272 | да | да | да | да | да | 48% |
| `securecode_ai.adapters.local_product_runner` | 454 | да | да | да | да | да | 14% |
| `securecode_ai.adapters.local_product_runner_cancellation` | 29 | да | да | да | да | да | 68% |
| `securecode_ai.adapters.local_product_runner_config` | 343 | да | да | да | да | да | 75% |
| `securecode_ai.adapters.local_product_runner_execution` | 829 | да | да | да | да | да | 79% |
| `securecode_ai.adapters.local_product_runner_execution_family` | 28 | да | да | да | да | да | 86% |
| `securecode_ai.adapters.local_product_runner_execution_types` | 21 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.local_product_runner_identity` | 47 | да | да | да | да | да | 50% |
| `securecode_ai.adapters.local_product_runner_roles` | 39 | да | да | да | да | да | 87% |
| `securecode_ai.adapters.local_product_scope` | 87 | да | да | да | да | да | 88% |
| `securecode_ai.adapters.local_product_trial` | 727 | да | нет | да | да | да | 73% |
| `securecode_ai.adapters.local_provider_admission` | 64 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.local_provider_admission_models` | 386 | да | да | да | да | да | 94% |
| `securecode_ai.adapters.local_provider_admission_validation` | 398 | нет | да | да | да | да | 81% |
| `securecode_ai.adapters.local_provider_gateway` | 76 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.local_provider_gateway_backend` | 422 | да | да | да | да | да | 21% |
| `securecode_ai.adapters.local_provider_gateway_handler` | 452 | да | да | да | да | да | 67% |
| `securecode_ai.adapters.local_provider_gateway_server` | 506 | да | да | да | да | да | 9% |
| `securecode_ai.adapters.local_provider_gateway_transforms` | 504 | да | да | да | да | да | 74% |
| `securecode_ai.adapters.local_provider_gateway_types` | 283 | да | да | да | да | да | 97% |
| `securecode_ai.adapters.local_repair` | 662 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_command_oracle` | 551 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_contracts` | 490 | нет | да | да | да | да | 41% |
| `securecode_ai.adapters.local_repair_diff` | 145 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_model` | 592 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_model_payload` | 170 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_model_schema` | 84 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_broker` | 767 | нет | нет | нет | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_child` | 687 | нет | нет | нет | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_commands` | 246 | нет | нет | нет | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_isolation` | 108 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_protocol` | 409 | нет | да | да | да | да | 32% |
| `securecode_ai.adapters.local_repair_oci_provider` | 621 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_runtime` | 732 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_oci_transport` | 463 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.local_repair_root_cause_oracle` | 353 | нет | нет | нет | да | да | 29% |
| `securecode_ai.adapters.local_repair_security_scan` | 74 | нет | нет | нет | да | да | 95% |
| `securecode_ai.adapters.local_repair_validation` | 330 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.masked_sources` | 78 | да | да | да | да | да | 28% |
| `securecode_ai.adapters.model` | 60 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.model_egress` | 65 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.model_fake` | 138 | да | да | да | да | да | 85% |
| `securecode_ai.adapters.model_harness` | 518 | да | да | да | да | да | 88% |
| `securecode_ai.adapters.model_normalization` | 266 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.model_parsing` | 424 | да | да | да | да | да | 80% |
| `securecode_ai.adapters.model_types` | 524 | да | да | да | да | да | 81% |
| `securecode_ai.adapters.native_repository_tools` | 235 | да | да | да | да | да | 98% |
| `securecode_ai.adapters.native_sources` | 381 | да | да | да | да | да | 74% |
| `securecode_ai.adapters.oci_sandbox` | 465 | нет | да | да | да | да | 0% |
| `securecode_ai.adapters.openai_compatible_local` | 15 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.openai_compatible_local_codec` | 206 | да | да | да | да | да | 85% |
| `securecode_ai.adapters.openai_compatible_local_transport` | 543 | да | да | да | да | да | 69% |
| `securecode_ai.adapters.openai_compatible_remote` | 995 | да | да | да | да | да | 38% |
| `securecode_ai.adapters.otlp_http` | 205 | да | да | да | да | да | 73% |
| `securecode_ai.adapters.patch_artifact` | 506 | да | да | да | да | да | 17% |
| `securecode_ai.adapters.product_audit` | 684 | да | да | да | да | да | 63% |
| `securecode_ai.adapters.product_audit_common` | 84 | да | да | да | да | да | 95% |
| `securecode_ai.adapters.product_audit_coverage` | 330 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.product_audit_findings` | 329 | да | да | да | да | да | 66% |
| `securecode_ai.adapters.product_audit_types` | 373 | да | да | да | да | да | 82% |
| `securecode_ai.adapters.product_audit_validation` | 548 | да | да | да | да | да | 75% |
| `securecode_ai.adapters.product_conformance` | 509 | нет | нет | нет | да | да | 87% |
| `securecode_ai.adapters.product_execution` | 87 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_execution_facts` | 556 | да | да | да | да | да | 46% |
| `securecode_ai.adapters.product_execution_orchestration` | 223 | да | да | да | да | да | 74% |
| `securecode_ai.adapters.product_execution_stages` | 460 | да | да | да | да | да | 70% |
| `securecode_ai.adapters.product_model` | 542 | да | да | да | да | да | 92% |
| `securecode_ai.adapters.product_provider_runtime` | 420 | да | да | да | да | да | 22% |
| `securecode_ai.adapters.product_review` | 31 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_review_contracts` | 111 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_review_execution` | 384 | да | да | да | да | да | 77% |
| `securecode_ai.adapters.product_review_hashes` | 191 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_rule_catalogue` | 123 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_runtime` | 71 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_runtime_auditor` | 264 | да | да | да | да | да | 76% |
| `securecode_ai.adapters.product_runtime_contracts` | 588 | да | да | да | да | да | 85% |
| `securecode_ai.adapters.product_runtime_discovery` | 404 | да | да | да | да | да | 76% |
| `securecode_ai.adapters.product_runtime_discovery_native` | 546 | да | да | да | да | да | 81% |
| `securecode_ai.adapters.product_runtime_discovery_native_observation` | 100 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.product_runtime_execution` | 595 | да | да | да | да | да | 78% |
| `securecode_ai.adapters.product_runtime_native` | 128 | да | да | да | да | да | 81% |
| `securecode_ai.adapters.product_runtime_seed` | 86 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_runtime_support` | 63 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_scan` | 371 | да | да | да | да | да | 81% |
| `securecode_ai.adapters.product_scanner` | 650 | да | да | да | да | да | 67% |
| `securecode_ai.adapters.product_scanner_evidence` | 745 | да | да | да | да | да | 89% |
| `securecode_ai.adapters.product_scanner_graph` | 677 | да | да | да | да | да | 50% |
| `securecode_ai.adapters.product_scanner_manifest` | 143 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_scanner_worker_common` | 213 | да | да | да | да | да | 78% |
| `securecode_ai.adapters.product_scanner_worker_ecmascript` | 425 | да | да | да | да | да | 64% |
| `securecode_ai.adapters.product_scanner_worker_go` | 394 | да | да | да | да | да | 64% |
| `securecode_ai.adapters.product_scanner_worker_python` | 411 | да | да | да | да | да | 67% |
| `securecode_ai.adapters.product_scanner_worker_support` | 129 | да | да | да | да | да | 80% |
| `securecode_ai.adapters.product_skeptic` | 23 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.product_skeptic_context` | 123 | да | да | да | да | да | 85% |
| `securecode_ai.adapters.product_skeptic_contracts` | 198 | да | да | да | да | да | 84% |
| `securecode_ai.adapters.product_skeptic_port` | 287 | да | да | да | да | да | 73% |
| `securecode_ai.adapters.product_skeptic_validator` | 159 | да | да | да | да | да | 83% |
| `securecode_ai.adapters.program_graph` | 397 | да | да | да | да | да | 89% |
| `securecode_ai.adapters.public_core_execution` | 525 | нет | нет | нет | да | да | 87% |
| `securecode_ai.adapters.public_core_fixtures` | 305 | нет | нет | нет | да | да | 95% |
| `securecode_ai.adapters.public_core_runner` | 96 | нет | нет | нет | да | да | 100% |
| `securecode_ai.adapters.public_core_runner_composition` | 254 | нет | нет | нет | да | да | 80% |
| `securecode_ai.adapters.public_core_runner_loader` | 82 | нет | нет | нет | да | да | 92% |
| `securecode_ai.adapters.public_core_runner_primitives` | 502 | нет | нет | нет | да | да | 80% |
| `securecode_ai.adapters.public_core_runner_runner` | 263 | нет | нет | нет | да | да | 75% |
| `securecode_ai.adapters.public_discovery_observation` | 455 | нет | нет | нет | да | да | 84% |
| `securecode_ai.adapters.public_gateway_observation` | 180 | да | да | да | да | да | 83% |
| `securecode_ai.adapters.python_ast` | 367 | да | да | да | да | да | 94% |
| `securecode_ai.adapters.python_cwe117` | 1365 | да | да | да | да | да | 43% |
| `securecode_ai.adapters.python_cwe1333` | 1207 | да | да | да | да | да | 38% |
| `securecode_ai.adapters.python_cwe209` | 1306 | да | да | да | да | да | 51% |
| `securecode_ai.adapters.python_cwe295` | 1006 | да | да | да | да | да | 56% |
| `securecode_ai.adapters.python_cwe306` | 1239 | да | да | да | да | да | 50% |
| `securecode_ai.adapters.python_cwe307` | 1001 | да | да | да | да | да | 51% |
| `securecode_ai.adapters.python_cwe327` | 803 | да | да | да | да | да | 59% |
| `securecode_ai.adapters.python_cwe338` | 1002 | да | да | да | да | да | 63% |
| `securecode_ai.adapters.python_cwe352` | 799 | да | да | да | да | да | 56% |
| `securecode_ai.adapters.python_cwe384` | 965 | да | да | да | да | да | 42% |
| `securecode_ai.adapters.python_cwe400` | 1420 | да | да | да | да | да | 56% |
| `securecode_ai.adapters.python_cwe476` | 1149 | да | да | да | да | да | 61% |
| `securecode_ai.adapters.python_cwe502` | 902 | да | да | да | да | да | 53% |
| `securecode_ai.adapters.python_cwe521` | 1084 | да | да | да | да | да | 43% |
| `securecode_ai.adapters.python_cwe532` | 1086 | да | да | да | да | да | 53% |
| `securecode_ai.adapters.python_cwe598` | 818 | да | да | да | да | да | 65% |
| `securecode_ai.adapters.python_cwe601` | 1222 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.python_cwe611` | 1093 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.python_cwe613` | 880 | да | да | да | да | да | 59% |
| `securecode_ai.adapters.python_cwe614` | 865 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.python_cwe639` | 900 | да | да | да | да | да | 45% |
| `securecode_ai.adapters.python_cwe732` | 1000 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.python_cwe776` | 1136 | да | да | да | да | да | 44% |
| `securecode_ai.adapters.python_cwe78` | 1316 | да | да | да | да | да | 67% |
| `securecode_ai.adapters.python_cwe79` | 1335 | да | да | да | да | да | 64% |
| `securecode_ai.adapters.python_cwe798` | 1122 | да | да | да | да | да | 54% |
| `securecode_ai.adapters.python_cwe862` | 754 | да | да | да | да | да | 76% |
| `securecode_ai.adapters.python_cwe90` | 1251 | да | да | да | да | да | 43% |
| `securecode_ai.adapters.python_cwe918` | 1376 | да | да | да | да | да | 64% |
| `securecode_ai.adapters.python_cwe94` | 730 | да | да | да | да | да | 59% |
| `securecode_ai.adapters.release_authorization` | 79 | да | нет | да | да | да | 44% |
| `securecode_ai.adapters.release_cli_config` | 419 | да | нет | да | да | да | 12% |
| `securecode_ai.adapters.release_provider` | 864 | да | нет | да | да | да | 10% |
| `securecode_ai.adapters.release_provider_support` | 840 | да | нет | да | да | да | 15% |
| `securecode_ai.adapters.remote_provider_budget` | 580 | да | да | да | да | да | 74% |
| `securecode_ai.adapters.remote_provider_budget_config` | 69 | нет | нет | нет | да | да | 28% |
| `securecode_ai.adapters.remote_provider_budget_sqlite` | 734 | да | да | да | да | да | 15% |
| `securecode_ai.adapters.repository` | 582 | да | да | да | да | да | 61% |
| `securecode_ai.adapters.repository_view` | 170 | да | да | да | да | да | 83% |
| `securecode_ai.adapters.runtime` | 9 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.scanner_plugin` | 505 | да | да | да | да | да | 67% |
| `securecode_ai.adapters.scm_artifacts` | 676 | нет | нет | нет | да | да | 88% |
| `securecode_ai.adapters.scm_diff` | 237 | нет | да | нет | да | да | 7% |
| `securecode_ai.adapters.scm_head` | 365 | нет | да | нет | да | да | 38% |
| `securecode_ai.adapters.secret_detection` | 49 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.secret_detection_models` | 309 | да | да | да | да | да | 90% |
| `securecode_ai.adapters.secret_detection_scan` | 409 | да | да | да | да | да | 90% |
| `securecode_ai.adapters.telemetry` | 237 | да | да | да | да | да | 88% |
| `securecode_ai.adapters.trace` | 91 | да | да | да | да | да | 100% |
| `securecode_ai.adapters.trial_architect` | 566 | да | нет | да | да | да | 84% |
| `securecode_ai.adapters.trial_baseline` | 218 | да | нет | да | да | да | 95% |
| `securecode_ai.adapters.trial_fix_export` | 375 | да | нет | да | да | да | 92% |
| `securecode_ai.adapters.trial_groups` | 79 | да | нет | да | да | да | 92% |
| `securecode_ai.adapters.trial_report` | 667 | да | нет | да | да | да | 95% |
| `securecode_ai.adapters.trial_unresolved` | 284 | да | нет | да | да | да | 84% |
| `securecode_ai.adapters.untrusted_contribution` | 481 | нет | да | нет | да | да | 87% |
| `securecode_ai.cli` | 54 | да | нет | да | да | да | 100% |
| `securecode_ai.cli.__main__` | 5 | нет | нет | да | да | да | 0% |
| `securecode_ai.cli.analyze` | 682 | да | нет | да | да | да | 52% |
| `securecode_ai.cli.application` | 380 | да | нет | да | да | да | 85% |
| `securecode_ai.cli.application_commands` | 416 | да | нет | да | да | да | 81% |
| `securecode_ai.cli.application_parser` | 266 | да | нет | да | да | да | 57% |
| `securecode_ai.cli.application_profiles` | 210 | да | нет | да | да | да | 96% |
| `securecode_ai.cli.approval` | 319 | да | нет | да | да | да | 10% |
| `securecode_ai.cli.atomic_output` | 326 | да | нет | да | да | да | 59% |
| `securecode_ai.cli.connected` | 167 | да | нет | да | да | да | 100% |
| `securecode_ai.cli.connected_approvals` | 685 | да | нет | да | да | да | 62% |
| `securecode_ai.cli.connected_ci_commands` | 164 | да | нет | да | да | да | 39% |
| `securecode_ai.cli.connected_cli_commands` | 43 | да | нет | да | да | да | 100% |
| `securecode_ai.cli.connected_cli_lifecycle` | 496 | да | нет | да | да | да | 4% |
| `securecode_ai.cli.connected_cli_readouts` | 373 | да | нет | да | да | да | 8% |
| `securecode_ai.cli.connected_feedback` | 618 | да | нет | да | да | да | 17% |
| `securecode_ai.cli.connected_lifecycle` | 1057 | да | нет | да | да | да | 29% |
| `securecode_ai.cli.connected_payload` | 38 | да | нет | да | да | да | 90% |
| `securecode_ai.cli.connected_policy_admin` | 495 | да | нет | да | да | да | 13% |
| `securecode_ai.cli.connected_runs` | 1594 | да | нет | да | да | да | 32% |
| `securecode_ai.cli.connected_transport` | 646 | да | нет | да | да | да | 36% |
| `securecode_ai.cli.connected_validation` | 25 | да | нет | да | да | да | 53% |
| `securecode_ai.cli.diagnostic` | 525 | да | нет | да | да | да | 69% |
| `securecode_ai.cli.publish` | 151 | нет | нет | да | да | да | 93% |
| `securecode_ai.cli.release` | 655 | да | нет | да | да | да | 13% |
| `securecode_ai.cli.repair` | 464 | да | нет | да | да | да | 45% |
| `securecode_ai.cli.scan` | 263 | да | нет | да | да | да | 61% |
| `securecode_ai.contracts` | 288 | да | да | да | да | да | 100% |
| `securecode_ai.contracts.base` | 108 | да | да | да | да | да | 97% |
| `securecode_ai.contracts.cli` | 352 | да | да | да | да | да | 99% |
| `securecode_ai.contracts.config` | 369 | да | да | да | да | да | 97% |
| `securecode_ai.contracts.domain` | 168 | да | да | да | да | да | 100% |
| `securecode_ai.contracts.domain_coverage` | 477 | да | да | да | да | да | 83% |
| `securecode_ai.contracts.domain_discovery` | 276 | да | да | да | да | да | 86% |
| `securecode_ai.contracts.domain_primitives` | 310 | да | да | да | да | да | 100% |
| `securecode_ai.contracts.domain_results` | 287 | да | да | да | да | да | 85% |
| `securecode_ai.contracts.events` | 526 | да | да | да | да | да | 87% |
| `securecode_ai.contracts.ids` | 95 | да | да | да | да | да | 100% |
| `securecode_ai.contracts.model` | 534 | да | да | да | да | да | 87% |
| `securecode_ai.contracts.runtime` | 136 | да | да | да | да | да | 100% |
| `securecode_ai.contracts.runtime_contract_definition` | 368 | да | да | да | да | да | 87% |
| `securecode_ai.contracts.runtime_contract_journal` | 429 | да | да | да | да | да | 73% |
| `securecode_ai.contracts.runtime_contract_requests` | 192 | да | да | да | да | да | 80% |
| `securecode_ai.contracts.schema_export` | 209 | нет | нет | нет | да | да | 79% |
| `securecode_ai.core` | 461 | да | да | да | да | да | 100% |
| `securecode_ai.core.ablation_metrics` | 84 | нет | нет | нет | да | да | 51% |
| `securecode_ai.core.ablation_study` | 175 | нет | нет | нет | да | да | 75% |
| `securecode_ai.core.architect` | 464 | да | да | да | да | да | 81% |
| `securecode_ai.core.auditor` | 187 | да | да | да | да | да | 89% |
| `securecode_ai.core.baseline_fingerprints` | 526 | да | да | да | да | да | 70% |
| `securecode_ai.core.classification` | 423 | да | да | да | да | да | 98% |
| `securecode_ai.core.code_index` | 156 | нет | нет | нет | да | да | 49% |
| `securecode_ai.core.config` | 5 | да | да | да | да | да | 100% |
| `securecode_ai.core.convergence` | 405 | нет | нет | нет | да | да | 71% |
| `securecode_ai.core.core_model_authorizations` | 142 | да | да | да | да | да | 85% |
| `securecode_ai.core.core_model_issuer` | 368 | да | да | да | да | да | 96% |
| `securecode_ai.core.core_model_protocols` | 189 | да | да | да | да | да | 87% |
| `securecode_ai.core.development_benchmark` | 23 | нет | нет | нет | да | да | 100% |
| `securecode_ai.core.development_benchmark_aggregate` | 403 | нет | нет | нет | да | да | 89% |
| `securecode_ai.core.development_benchmark_math` | 41 | нет | нет | нет | да | да | 63% |
| `securecode_ai.core.development_benchmark_models` | 301 | нет | нет | нет | да | да | 81% |
| `securecode_ai.core.diff_review` | 442 | нет | да | да | да | да | 93% |
| `securecode_ai.core.discovery` | 75 | да | да | да | да | да | 100% |
| `securecode_ai.core.discovery_changed` | 205 | да | да | да | да | да | 89% |
| `securecode_ai.core.discovery_primitives` | 561 | да | да | да | да | да | 94% |
| `securecode_ai.core.discovery_repository` | 101 | да | да | да | да | да | 96% |
| `securecode_ai.core.escalation` | 462 | нет | нет | нет | да | да | 85% |
| `securecode_ai.core.evaluation_access` | 266 | нет | нет | нет | да | да | 86% |
| `securecode_ai.core.evaluation_authority` | 440 | нет | нет | нет | да | да | 77% |
| `securecode_ai.core.evaluation_candidate_store` | 195 | нет | нет | нет | да | да | 84% |
| `securecode_ai.core.evaluation_lab` | 502 | нет | нет | нет | да | да | 79% |
| `securecode_ai.core.evaluation_lab_evidence` | 260 | нет | нет | нет | да | да | 95% |
| `securecode_ai.core.evaluation_lab_models` | 266 | нет | нет | нет | да | да | 91% |
| `securecode_ai.core.events` | 475 | да | да | да | да | да | 93% |
| `securecode_ai.core.evidence_graph` | 420 | да | да | да | да | да | 89% |
| `securecode_ai.core.evidence_package` | 343 | да | да | да | да | да | 90% |
| `securecode_ai.core.finding_gate` | 574 | да | да | да | да | да | 93% |
| `securecode_ai.core.finding_validation` | 322 | нет | нет | нет | да | да | 83% |
| `securecode_ai.core.injection_boundary` | 480 | да | да | да | да | да | 84% |
| `securecode_ai.core.investigation` | 57 | да | да | да | да | да | 100% |
| `securecode_ai.core.investigation_helpers` | 234 | да | да | да | да | да | 81% |
| `securecode_ai.core.investigation_models` | 304 | да | да | да | да | да | 88% |
| `securecode_ai.core.investigation_runner` | 271 | да | да | да | да | да | 81% |
| `securecode_ai.core.investigation_telemetry` | 278 | нет | нет | нет | да | да | 84% |
| `securecode_ai.core.model` | 51 | да | да | да | да | да | 100% |
| `securecode_ai.core.model_discovery` | 48 | да | да | да | да | да | 100% |
| `securecode_ai.core.model_discovery_contracts` | 377 | да | да | да | да | да | 92% |
| `securecode_ai.core.model_discovery_runner` | 308 | да | да | да | да | да | 89% |
| `securecode_ai.core.normalization` | 471 | да | да | да | да | да | 84% |
| `securecode_ai.core.offline_optimization` | 462 | нет | нет | нет | да | да | 82% |
| `securecode_ai.core.offline_optimization_authority` | 223 | нет | нет | нет | да | да | 77% |
| `securecode_ai.core.offline_optimization_evidence` | 48 | нет | нет | нет | да | да | 100% |
| `securecode_ai.core.operational_telemetry` | 101 | да | да | да | да | да | 72% |
| `securecode_ai.core.optimization_candidates` | 156 | нет | нет | нет | да | да | 91% |
| `securecode_ai.core.optimization_promotion` | 254 | нет | нет | нет | да | да | 82% |
| `securecode_ai.core.patch_status` | 39 | нет | да | да | да | да | 100% |
| `securecode_ai.core.patch_status_helpers` | 430 | нет | да | да | да | да | 80% |
| `securecode_ai.core.patch_status_models` | 234 | нет | да | да | да | да | 88% |
| `securecode_ai.core.patch_status_transitions` | 144 | нет | да | да | да | да | 85% |
| `securecode_ai.core.performance_budget` | 174 | нет | нет | нет | да | да | 47% |
| `securecode_ai.core.performance_regression` | 123 | нет | нет | нет | да | да | 25% |
| `securecode_ai.core.program_graph` | 388 | да | да | да | да | да | 89% |
| `securecode_ai.core.promotion_decision` | 599 | нет | нет | нет | да | да | 83% |
| `securecode_ai.core.promotion_registry` | 119 | нет | нет | нет | да | да | 83% |
| `securecode_ai.core.promotion_registry_store` | 323 | нет | нет | нет | да | да | 52% |
| `securecode_ai.core.regression` | 565 | да | да | да | да | да | 86% |
| `securecode_ai.core.release_benchmark` | 370 | нет | нет | нет | да | да | 43% |
| `securecode_ai.core.release_candidate` | 151 | да | нет | да | да | да | 88% |
| `securecode_ai.core.release_metrics` | 77 | нет | нет | нет | да | да | 100% |
| `securecode_ai.core.release_provenance` | 151 | да | нет | да | да | да | 34% |
| `securecode_ai.core.release_publisher` | 258 | да | нет | да | да | да | 72% |
| `securecode_ai.core.repair_loop` | 442 | да | да | да | да | да | 41% |
| `securecode_ai.core.reports` | 50 | да | да | да | да | да | 100% |
| `securecode_ai.core.reports_build` | 143 | да | да | да | да | да | 77% |
| `securecode_ai.core.reports_contracts` | 98 | да | да | да | да | да | 93% |
| `securecode_ai.core.reports_render` | 216 | да | да | да | да | да | 88% |
| `securecode_ai.core.reports_sarif` | 288 | да | да | да | да | да | 86% |
| `securecode_ai.core.repository` | 147 | да | да | да | да | да | 88% |
| `securecode_ai.core.resource_governor` | 487 | нет | да | нет | да | да | 45% |
| `securecode_ai.core.rlm_experiment` | 94 | нет | нет | нет | да | да | 89% |
| `securecode_ai.core.root_cause` | 484 | да | да | да | да | да | 81% |
| `securecode_ai.core.runtime` | 48 | да | да | да | да | да | 100% |
| `securecode_ai.core.runtime_actions` | 367 | да | да | да | да | да | 80% |
| `securecode_ai.core.runtime_definition` | 330 | да | да | да | да | да | 89% |
| `securecode_ai.core.runtime_transition` | 472 | да | да | да | да | да | 93% |
| `securecode_ai.core.sandbox` | 522 | да | да | да | да | да | 81% |
| `securecode_ai.core.scanning` | 321 | да | да | да | да | да | 77% |
| `securecode_ai.core.scm_policy` | 1208 | да | да | да | да | да | 71% |
| `securecode_ai.core.scm_run_state` | 415 | нет | да | нет | да | да | 94% |
| `securecode_ai.core.security_invariants` | 546 | да | да | да | да | да | 83% |
| `securecode_ai.core.skeptic` | 381 | да | да | да | да | да | 81% |
| `securecode_ai.core.supply_chain` | 120 | да | нет | да | да | да | 100% |
| `securecode_ai.core.symbols` | 660 | да | да | да | да | да | 88% |
| `securecode_ai.core.synthetic_cases` | 210 | нет | нет | нет | да | да | 84% |
| `securecode_ai.core.synthetic_lineage` | 273 | нет | нет | нет | да | да | 89% |
| `securecode_ai.core.synthetic_oracle` | 175 | нет | нет | нет | да | да | 83% |
| `securecode_ai.core.telemetry` | 108 | да | да | да | да | да | 100% |
| `securecode_ai.core.telemetry_authority` | 169 | да | да | да | да | да | 80% |
| `securecode_ai.core.telemetry_emitter` | 398 | да | да | да | да | да | 83% |
| `securecode_ai.core.telemetry_opener` | 204 | да | да | да | да | да | 82% |
| `securecode_ai.core.telemetry_parsing` | 150 | да | да | да | да | да | 79% |
| `securecode_ai.core.telemetry_primitives` | 465 | да | да | да | да | да | 84% |
| `securecode_ai.core.tool_policy` | 504 | да | да | да | да | да | 88% |
| `securecode_ai.core.validation` | 550 | да | да | да | да | да | 83% |
| `securecode_ai.core.validation_promotion` | 138 | нет | нет | нет | да | да | 89% |
| `securecode_ai.server` | 31 | нет | да | нет | да | да | 100% |
| `securecode_ai.server.alerts` | 64 | нет | да | нет | да | да | 86% |
| `securecode_ai.server.application` | 911 | нет | да | нет | да | да | 51% |
| `securecode_ai.server.approvals` | 943 | нет | да | нет | да | да | 57% |
| `securecode_ai.server.artifact_read` | 757 | нет | да | нет | да | да | 13% |
| `securecode_ai.server.artifact_store` | 528 | нет | да | нет | да | да | 56% |
| `securecode_ai.server.artifact_tenant_namespace` | 33 | нет | да | нет | да | да | 87% |
| `securecode_ai.server.artifact_upload` | 1051 | нет | да | нет | да | да | 54% |
| `securecode_ai.server.artifact_upload_handler` | 128 | нет | да | нет | да | да | 16% |
| `securecode_ai.server.artifact_upload_verifier` | 230 | нет | да | нет | да | да | 17% |
| `securecode_ai.server.artifacts` | 77 | нет | да | нет | да | да | 79% |
| `securecode_ai.server.assurance_pins_source` | 175 | нет | да | нет | да | да | 21% |
| `securecode_ai.server.assurance_reports` | 222 | нет | да | нет | да | да | 73% |
| `securecode_ai.server.assurance_repository` | 447 | нет | да | нет | да | да | 61% |
| `securecode_ai.server.assurance_service` | 117 | нет | да | нет | да | да | 38% |
| `securecode_ai.server.assurance_verifiers` | 150 | нет | да | нет | да | да | 21% |
| `securecode_ai.server.audit_export` | 158 | нет | да | нет | да | да | 51% |
| `securecode_ai.server.audit_log` | 1348 | нет | да | нет | да | да | 50% |
| `securecode_ai.server.auth_configuration` | 498 | нет | да | нет | да | да | 12% |
| `securecode_ai.server.auth_crypto` | 62 | нет | да | нет | да | да | 36% |
| `securecode_ai.server.auth_runtime` | 664 | нет | да | нет | да | да | 72% |
| `securecode_ai.server.backup_executor_runtime` | 1262 | нет | да | нет | да | да | 10% |
| `securecode_ai.server.backup_lifecycle` | 1080 | нет | да | нет | да | да | 14% |
| `securecode_ai.server.backup_repository` | 982 | нет | да | нет | да | да | 60% |
| `securecode_ai.server.backup_service` | 839 | нет | да | нет | да | да | 55% |
| `securecode_ai.server.baseline_store` | 260 | нет | да | нет | да | да | 71% |
| `securecode_ai.server.bootstrap` | 849 | нет | да | нет | да | да | 34% |
| `securecode_ai.server.bootstrap_identity` | 153 | нет | да | нет | да | да | 24% |
| `securecode_ai.server.capacity` | 212 | нет | да | нет | да | да | 82% |
| `securecode_ai.server.capacity_cli` | 513 | нет | да | нет | да | да | 0% |
| `securecode_ai.server.capacity_profile` | 820 | нет | да | нет | да | да | 54% |
| `securecode_ai.server.chaos` | 34 | нет | да | нет | да | да | 100% |
| `securecode_ai.server.checkpoints` | 92 | нет | да | нет | да | да | 87% |
| `securecode_ai.server.composite_readiness` | 28 | нет | да | нет | да | да | 30% |
| `securecode_ai.server.composite_service` | 96 | нет | да | нет | да | да | 54% |
| `securecode_ai.server.data_lifecycle` | 1147 | нет | да | нет | да | да | 47% |
| `securecode_ai.server.data_lifecycle_models` | 151 | нет | да | нет | да | да | 79% |
| `securecode_ai.server.enterprise` | 106 | нет | да | нет | да | да | 69% |
| `securecode_ai.server.enterprise_service` | 309 | нет | да | нет | да | да | 46% |
| `securecode_ai.server.evidence_egress` | 412 | нет | да | нет | да | да | 51% |
| `securecode_ai.server.evidence_packages` | 115 | нет | да | нет | да | да | 85% |
| `securecode_ai.server.feedback_repository` | 243 | нет | да | нет | да | да | 65% |
| `securecode_ai.server.feedback_service` | 95 | нет | да | нет | да | да | 67% |
| `securecode_ai.server.filesystem_paths` | 26 | нет | да | нет | да | да | 60% |
| `securecode_ai.server.finding_evidence` | 303 | нет | да | нет | да | да | 65% |
| `securecode_ai.server.http_boundary` | 405 | нет | да | нет | да | да | 76% |
| `securecode_ai.server.http_server` | 440 | нет | да | нет | да | да | 0% |
| `securecode_ai.server.idempotency` | 508 | нет | да | нет | да | да | 30% |
| `securecode_ai.server.identity` | 111 | нет | да | нет | да | да | 84% |
| `securecode_ai.server.json_boundary` | 106 | нет | да | нет | да | да | 57% |
| `securecode_ai.server.lifecycle_scheduler` | 382 | нет | да | нет | да | да | 15% |
| `securecode_ai.server.main` | 87 | нет | да | нет | да | да | 0% |
| `securecode_ai.server.maintenance_cli` | 948 | нет | да | нет | да | да | 18% |
| `securecode_ai.server.maintenance_daemon` | 145 | нет | да | нет | да | да | 0% |
| `securecode_ai.server.migrations` | 908 | нет | да | нет | да | да | 56% |
| `securecode_ai.server.observability` | 43 | нет | да | нет | да | да | 83% |
| `securecode_ai.server.oidc` | 402 | нет | да | нет | да | да | 63% |
| `securecode_ai.server.oidc_login` | 656 | нет | да | нет | да | да | 79% |
| `securecode_ai.server.oidc_sessions` | 607 | нет | да | нет | да | да | 47% |
| `securecode_ai.server.openapi` | 448 | нет | да | нет | да | да | 94% |
| `securecode_ai.server.operations_audit` | 685 | нет | да | нет | да | да | 54% |
| `securecode_ai.server.operations_handler_backup` | 372 | нет | да | нет | да | да | 46% |
| `securecode_ai.server.operations_handler_common` | 182 | нет | да | нет | да | да | 36% |
| `securecode_ai.server.operations_handler_evidence` | 338 | нет | да | нет | да | да | 14% |
| `securecode_ai.server.operations_handler_governance` | 579 | нет | да | нет | да | да | 10% |
| `securecode_ai.server.operations_handler_secrets` | 347 | нет | да | нет | да | да | 11% |
| `securecode_ai.server.operations_handler_waivers` | 295 | нет | да | нет | да | да | 13% |
| `securecode_ai.server.operations_runtime` | 87 | нет | да | нет | да | да | 67% |
| `securecode_ai.server.operations_telemetry` | 418 | нет | да | нет | да | да | 44% |
| `securecode_ai.server.osv_relay` | 162 | нет | да | нет | да | да | 23% |
| `securecode_ai.server.persistence` | 955 | нет | да | нет | да | да | 51% |
| `securecode_ai.server.policy_operations` | 220 | нет | да | нет | да | да | 13% |
| `securecode_ai.server.policy_store` | 799 | нет | да | нет | да | да | 56% |
| `securecode_ai.server.ports` | 116 | нет | да | нет | да | да | 89% |
| `securecode_ai.server.postgres_oidc_rate_limiter` | 290 | нет | да | нет | да | да | 0% |
| `securecode_ai.server.profiles` | 115 | нет | да | нет | да | да | 92% |
| `securecode_ai.server.query_service` | 175 | нет | да | нет | да | да | 79% |
| `securecode_ai.server.reloading_identity` | 59 | нет | да | нет | да | да | 65% |
| `securecode_ai.server.request_quota` | 210 | нет | да | нет | да | да | 95% |
| `securecode_ai.server.request_scope` | 28 | нет | да | нет | да | да | 64% |
| `securecode_ai.server.residency` | 56 | нет | да | нет | да | да | 68% |
| `securecode_ai.server.residency_registry` | 428 | нет | да | нет | да | да | 15% |
| `securecode_ai.server.resilience` | 58 | нет | да | нет | да | да | 82% |
| `securecode_ai.server.resource_configuration` | 236 | нет | да | нет | да | да | 40% |
| `securecode_ai.server.resource_repository` | 825 | нет | да | нет | да | да | 28% |
| `securecode_ai.server.resource_service` | 209 | нет | да | нет | да | да | 64% |
| `securecode_ai.server.resource_storage` | 307 | нет | да | нет | да | да | 63% |
| `securecode_ai.server.retention_planner` | 943 | нет | да | нет | да | да | 17% |
| `securecode_ai.server.revalidation` | 26 | нет | да | нет | да | да | 100% |
| `securecode_ai.server.run_admission` | 660 | нет | да | нет | да | да | 12% |
| `securecode_ai.server.run_admission_models` | 373 | нет | да | нет | да | да | 62% |
| `securecode_ai.server.run_admission_store` | 569 | нет | да | нет | да | да | 42% |
| `securecode_ai.server.run_projection` | 37 | нет | да | нет | да | да | 69% |
| `securecode_ai.server.runtime` | 69 | нет | да | нет | да | да | 100% |
| `securecode_ai.server.scm_admission` | 383 | нет | да | нет | да | да | 24% |
| `securecode_ai.server.scm_annotations` | 331 | нет | да | нет | да | да | 17% |
| `securecode_ai.server.scm_completion` | 1155 | нет | да | нет | да | да | 29% |
| `securecode_ai.server.scm_completion_models` | 395 | нет | да | нет | да | да | 75% |
| `securecode_ai.server.scm_github_payload` | 39 | нет | да | нет | да | да | 26% |
| `securecode_ai.server.scm_gitlab_publication` | 335 | нет | да | нет | да | да | 15% |
| `securecode_ai.server.scm_payload` | 88 | нет | да | нет | да | да | 13% |
| `securecode_ai.server.scm_policy_registry` | 210 | нет | да | нет | да | да | 20% |
| `securecode_ai.server.scm_policy_waivers` | 65 | нет | да | нет | да | да | 33% |
| `securecode_ai.server.scm_publication_runtime` | 200 | нет | да | нет | да | да | 22% |
| `securecode_ai.server.scm_publication_store` | 404 | нет | да | нет | да | да | 22% |
| `securecode_ai.server.scm_reconciler` | 261 | нет | да | нет | да | да | 19% |
| `securecode_ai.server.scm_resolution` | 93 | нет | да | нет | да | да | 22% |
| `securecode_ai.server.scm_runtime` | 389 | нет | да | нет | да | да | 35% |
| `securecode_ai.server.scm_state` | 590 | нет | да | нет | да | да | 15% |
| `securecode_ai.server.scm_state_codec` | 283 | нет | да | нет | да | да | 26% |
| `securecode_ai.server.scm_state_schema` | 102 | нет | да | нет | да | да | 100% |
| `securecode_ai.server.scm_webhooks` | 980 | нет | да | нет | да | да | 30% |
| `securecode_ai.server.secret_provider` | 57 | нет | да | нет | да | да | 75% |
| `securecode_ai.server.secret_provider_runtime` | 190 | нет | да | нет | да | да | 38% |
| `securecode_ai.server.secret_service` | 948 | нет | да | нет | да | да | 41% |
| `securecode_ai.server.secure_files` | 212 | нет | да | нет | да | да | 12% |
| `securecode_ai.server.service` | 647 | нет | да | нет | да | да | 33% |
| `securecode_ai.server.sessions` | 786 | нет | да | нет | да | да | 23% |
| `securecode_ai.server.sli` | 96 | нет | да | нет | да | да | 48% |
| `securecode_ai.server.sqlite_database` | 211 | нет | да | нет | да | да | 13% |
| `securecode_ai.server.sqlite_rate_limiter` | 210 | нет | да | нет | да | да | 15% |
| `securecode_ai.server.sqlite_remote_provider_budget` | 1064 | нет | да | нет | да | да | 0% |
| `securecode_ai.server.sqlite_request_quota` | 411 | нет | да | нет | да | да | 54% |
| `securecode_ai.server.storage_executor` | 828 | нет | да | нет | да | да | 14% |
| `securecode_ai.server.subprocess_protocol` | 394 | нет | да | нет | да | да | 11% |
| `securecode_ai.server.system_backup_runtime` | 1169 | нет | да | нет | да | да | 10% |
| `securecode_ai.server.telemetry` | 301 | нет | да | нет | да | да | 73% |
| `securecode_ai.server.tenant_key_migration` | 321 | нет | да | нет | да | да | 23% |
| `securecode_ai.server.tenant_rate_limiter` | 188 | нет | да | нет | да | да | 66% |
| `securecode_ai.server.views` | 70 | нет | да | нет | да | да | 90% |
| `securecode_ai.server.waivers` | 875 | нет | да | нет | да | да | 23% |
| `securecode_ai.server.worker_artifact_authorization` | 903 | нет | да | нет | да | да | 65% |
| `securecode_ai.server.worker_completion_evidence` | 630 | нет | да | нет | да | да | 63% |
| `securecode_ai.server.worker_findings` | 218 | нет | да | нет | да | да | 76% |
| `securecode_ai.server.worker_findings_store` | 463 | нет | да | нет | да | да | 55% |
| `securecode_ai.server.worker_queue` | 1229 | нет | да | нет | да | да | 43% |
| `securecode_ai.server.worker_queue_handler` | 826 | нет | да | нет | да | да | 16% |
| `securecode_ai.server.worker_queue_models` | 423 | нет | да | нет | да | да | 51% |
| `securecode_ai.server.worker_resource_accounting` | 596 | нет | да | нет | да | да | 17% |
| `securecode_ai.server.worker_resource_models` | 267 | нет | да | нет | да | да | 57% |
| `securecode_ai.server.worker_resource_store` | 236 | нет | да | нет | да | да | 19% |
| `securecode_ai.server.worker_scm_policy` | 351 | нет | да | нет | да | да | 75% |
| `securecode_ai.server.worker_sessions` | 414 | нет | да | нет | да | да | 46% |
| `securecode_ai.server.workflow` | 295 | нет | да | нет | да | да | 77% |
| `securecode_ai.worker` | 24 | нет | да | нет | нет | да | 100% |
| `securecode_ai.worker.artifacts` | 362 | нет | да | нет | нет | да | 20% |
| `securecode_ai.worker.cli` | 208 | нет | да | нет | нет | да | 56% |
| `securecode_ai.worker.control_plane` | 1098 | нет | да | нет | нет | да | 13% |
| `securecode_ai.worker.execution` | 944 | нет | да | нет | нет | да | 19% |
| `securecode_ai.worker.liveness` | 71 | нет | да | нет | нет | да | 60% |
| `securecode_ai.worker.protocol` | 539 | нет | да | нет | нет | да | 79% |
| `securecode_ai.worker.provider_gateway` | 360 | нет | да | нет | нет | да | 0% |
| `securecode_ai.worker.runner` | 248 | нет | да | нет | нет | да | 84% |
| `securecode_ai.worker.runtime_config` | 168 | нет | да | нет | нет | да | 34% |
| `securecode_ai.worker.secure_files` | 116 | нет | да | нет | нет | да | 15% |
| `securecode_ai.worker.service` | 1358 | нет | да | нет | нет | да | 38% |
| `securecode_ai.worker.service_state` | 88 | нет | да | нет | нет | да | 82% |
| `securecode_ai.worker.usage` | 616 | нет | да | нет | нет | да | 17% |
