#include "PassphraseLab.h"
#include "Passphrase.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <sstream>

namespace {
std::string to_lower(std::string s) {
  for (char& c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}
std::string to_upper_first(std::string s) {
  if (!s.empty()) s[0] = (char)std::toupper((unsigned char)s[0]);
  return s;
}
std::string leetify(std::string s) {
  for (char& c : s) {
    switch (std::tolower((unsigned char)c)) {
      case 'a':
        c = '4';
        break;
      case 'e':
        c = '3';
        break;
      case 'i':
        c = '1';
        break;
      case 'o':
        c = '0';
        break;
      case 's':
        c = '5';
        break;
      case 't':
        c = '7';
        break;
      default:
        break;
    }
  }
  return s;
}
}  // namespace

std::vector<std::string> apply_personality_mutants(const std::vector<std::string>& base,
                                                   const RecallTokens& tok, size_t max_out) {
  std::vector<std::string> out;
  auto push = [&](const std::string& s) {
    if (out.size() >= max_out) return;
    if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
  };
  for (const auto& b : base) {
    push(b);
    if (tok.case_variants) {
      push(to_lower(b));
      push(to_upper_first(b));
      std::string u = b;
      for (char& c : u) c = (char)std::toupper((unsigned char)c);
      push(u);
    }
    if (tok.leet) push(leetify(b));
    if (tok.append_years) {
      for (const auto& y : tok.years) {
        push(b + y);
        push(b + "!" + y);
        push(b + y + "!");
      }
    }
    for (const auto& suf : tok.suffixes) push(b + suf);
    for (const auto& pre : tok.prefixes) push(pre + b);
  }
  return out;
}

std::vector<std::string> generate_recall_candidates(const RecallTokens& tok, size_t max_out,
                                                    CandidateGenStats* stats) {
  std::vector<std::string> seps = tok.separators;
  if (seps.empty()) seps = {"", " ", "-", "_"};

  std::vector<std::string> cores;
  const auto& words = tok.known_words;
  if (words.empty()) {
    if (stats) {
      stats->count = 0;
      stats->summary = "no known words";
    }
    return {};
  }

  /* permutations of up to 4 words with separators */
  size_t n = words.size();
  if (n > 6) n = 6;
  std::vector<int> idx(n);
  for (size_t i = 0; i < n; ++i) idx[i] = (int)i;
  do {
    for (const auto& sep : seps) {
      std::string s;
      for (size_t i = 0; i < n; ++i) {
        if (i) s += sep;
        s += words[idx[i]];
      }
      cores.push_back(s);
      if (cores.size() >= max_out) break;
    }
    if (cores.size() >= max_out) break;
  } while (std::next_permutation(idx.begin(), idx.end()));

  /* also single words and pairs */
  for (const auto& w : words) cores.push_back(w);
  for (size_t i = 0; i < words.size(); ++i)
    for (size_t j = 0; j < words.size(); ++j)
      if (i != j)
        for (const auto& sep : seps) cores.push_back(words[i] + sep + words[j]);

  if (tok.keyboard_walks) {
    static const char* walks[] = {"qwerty", "qwertyuiop", "asdfgh", "zxcvbn",
                                  "1qaz2wsx", "qazwsx", "123456", "1234567890"};
    for (auto* w : walks) cores.push_back(w);
  }

  auto out = apply_personality_mutants(cores, tok, max_out);
  if (stats) {
    stats->count = out.size();
    stats->space_log10 = out.empty() ? 0 : std::log10((double)out.size());
    std::ostringstream o;
    o << out.size() << " candidates from " << words.size() << " words, " << seps.size()
      << " seps; mutants case=" << (tok.case_variants ? "on" : "off")
      << " leet=" << (tok.leet ? "on" : "off");
    stats->summary = o.str();
  }
  return out;
}

std::vector<std::string> expand_simple_mask(const std::string& mask, size_t max_out) {
  std::vector<std::string> cur = {""};
  for (size_t i = 0; i < mask.size();) {
    std::vector<std::string> next;
    if (mask[i] == '?' && i + 1 < mask.size()) {
      char t = mask[i + 1];
      std::string charset;
      if (t == 'd')
        charset = "0123456789";
      else if (t == 'l')
        charset = "abcdefghijklmnopqrstuvwxyz";
      else if (t == 'u')
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
      else if (t == 's')
        charset = "!@#$%^&*()-_";
      else if (t == '?')
        charset = "?";
      else
        charset = std::string(1, t);
      for (const auto& p : cur) {
        for (char c : charset) {
          next.push_back(p + c);
          if (next.size() >= max_out) break;
        }
        if (next.size() >= max_out) break;
      }
      i += 2;
    } else {
      for (const auto& p : cur) next.push_back(p + mask[i]);
      ++i;
    }
    cur.swap(next);
    if (cur.size() > max_out) {
      cur.resize(max_out);
      break;
    }
  }
  return cur;
}

std::string format_passphrase_eta(uint32_t iterations, uint64_t candidates, double hps) {
  std::ostringstream o;
  if (hps <= 0) {
    o << "ETA unknown (measure H/s first); iters=" << iterations
      << " candidates=" << candidates;
    return o.str();
  }
  double sec = (double)candidates / hps;
  o << "iters=" << iterations << " candidates=" << candidates << " @ " << hps << " H/s → ";
  if (sec < 60)
    o << sec << " s";
  else if (sec < 3600)
    o << (sec / 60.0) << " min";
  else if (sec < 86400)
    o << (sec / 3600.0) << " h";
  else
    o << (sec / 86400.0) << " d";
  return o.str();
}

double measure_kdf_hps(const MasterKeyInfo& mkey, int samples) {
  if (!mkey.found || mkey.salt.size() < 8) return 0;
  auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < samples; ++i) {
    std::string pass = "bench_pass_" + std::to_string(i);
    (void)try_wallet_passphrase(mkey, pass);
  }
  double sec =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  if (sec <= 0) return 0;
  return (double)samples / sec;
}

bool run_passphrase_batch(const WalletParseResult& wallet,
                          const std::vector<std::string>& candidates,
                          PassphraseCrackProgress& prog,
                          const std::string& found_file) {
  prog.running = true;
  prog.stop = false;
  prog.hit = false;
  prog.tried = 0;
  prog.total = candidates.size();
  prog.found_pass.clear();
  auto t0 = std::chrono::steady_clock::now();
  for (size_t i = 0; i < candidates.size(); ++i) {
    if (prog.stop.load()) {
      prog.message = "stopped";
      prog.running = false;
      return false;
    }
    auto dual = dual_verify_passphrase(wallet.mkey, wallet, candidates[i], found_file);
    prog.tried = i + 1;
    double sec =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (sec > 0) prog.rate_hps = (double)(i + 1) / sec;
    if (dual.ok) {
      prog.hit = true;
      prog.found_pass = candidates[i];
      prog.dual = dual;
      prog.message = "FOUND passphrase — " + dual.message;
      prog.running = false;
      return true;
    }
  }
  prog.message = "exhausted candidates (no hit)";
  prog.running = false;
  return false;
}
