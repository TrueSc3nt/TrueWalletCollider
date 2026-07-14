#pragma once
#include <string>

/** Built-in research harness (--experiment NAME). */
int run_experiment(const std::string& name, std::string* log_out);

/** Passphrase KDF selftest with crafted tiny encrypted mkey vector. */
int experiment_passphrase_selftest(std::string* log_out);

/** Dual-verifier FP rate demo. */
int experiment_dual_fp(std::string* log_out, int trials = 5000);

/** List experiment names. */
std::string experiment_help();
