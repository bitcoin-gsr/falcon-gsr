// Evaluate every input of a transaction with Core's consensus script checks and
// the BIP 440 transaction varops budget, and report the varops each input used.
//
// stdin: {"tx": "<hex>", "spent": [{"amount": <sat>, "script_pubkey": "<hex>"}, ...], "repeat": n}
// stdout: {"weight", "budget", "inputs": [{"success", "error", "varops", "median_us"}], "remaining"}
// With "repeat", each input is also verified n more times, with a fresh budget,
// and the median wall time of one VerifyScript call is reported. "budget_override"
// replaces the BIP 440 budget (a diagnostic: it reports what an unfunded input would use).
#include <consensus/validation.h>
#include <core_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script_error.h>
#include <script/varops.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <iterator>
#include <string>

int main()
{
    const std::string input{std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>()};
    UniValue request;
    if (!request.read(input)) {
        std::cerr << "bad JSON\n";
        return 1;
    }
    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, request["tx"].get_str())) {
        std::cerr << "bad tx\n";
        return 1;
    }
    const CTransaction tx{mtx};
    std::vector<CTxOut> spent;
    for (const UniValue& out : request["spent"].getValues()) {
        const auto spk{ParseHex(out["script_pubkey"].get_str())};
        spent.emplace_back(out["amount"].getInt<int64_t>(), CScript(spk.begin(), spk.end()));
    }
    if (spent.size() != tx.vin.size()) {
        std::cerr << "spent outputs do not match inputs\n";
        return 1;
    }
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::vector<CTxOut>{spent});
    const uint64_t budget_total{request.exists("budget_override") ? request["budget_override"].getInt<uint64_t>()
                                                                   : GetTransactionVaropsBudget(tx, spent)};
    varops::Budget budget{budget_total};
    UniValue inputs{UniValue::VARR};
    for (size_t i{0}; i < tx.vin.size(); ++i) {
        const uint64_t before{budget.Remaining()};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const TransactionSignatureChecker checker{&tx, static_cast<unsigned int>(i), spent[i].nValue, txdata, MissingDataBehavior::FAIL};
        const bool ok{VerifyScript(tx.vin[i].scriptSig, spent[i].scriptPubKey, &tx.vin[i].scriptWitness,
                                   STANDARD_SCRIPT_VERIFY_FLAGS, checker, &error, budget)};
        UniValue result{UniValue::VOBJ};
        result.pushKV("success", ok);
        result.pushKV("error", ScriptErrorString(error));
        result.pushKV("varops", before - budget.Remaining());
        const int repeat{request.exists("repeat") ? request["repeat"].getInt<int>() : 0};
        if (repeat > 0) {
            std::vector<double> times;
            for (int r{0}; r < repeat; ++r) {
                varops::Budget fresh{budget_total};
                const auto start{std::chrono::steady_clock::now()};
                (void)VerifyScript(tx.vin[i].scriptSig, spent[i].scriptPubKey, &tx.vin[i].scriptWitness,
                                   STANDARD_SCRIPT_VERIFY_FLAGS, checker, nullptr, fresh);
                times.push_back(std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - start).count());
            }
            std::sort(times.begin(), times.end());
            result.pushKV("median_us", times[times.size() / 2]);
        }
        inputs.push_back(std::move(result));
    }
    UniValue out{UniValue::VOBJ};
    out.pushKV("weight", GetTransactionWeight(tx));
    out.pushKV("budget", budget_total);
    out.pushKV("inputs", std::move(inputs));
    out.pushKV("remaining", budget.Remaining());
    std::cout << out.write() << '\n';
}
