// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <cassert>
#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

// Helper function

std::vector<unsigned char> hex_string_to_char_vec(std::string_view hex)
{
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i{0}; i < hex.length(); i += 2) {
        unsigned char byte;
        auto [ptr, ec] = std::from_chars(hex.data() + i, hex.data() + i + 2, byte, 16);
        if (ec == std::errc{} && ptr == hex.data() + i + 2) {
            bytes.push_back(byte);
        }
    }
    return bytes;
}

// Test Block Validation from kernel API

// static void DeserializeBlockKernelApiTest(benchmark::Bench& bench)
// {
//
//
//
//
// }

// Test Verify Script Kernel API Benchmarking

static void VerifyScriptKernelApiBench(benchmark::Bench& bench)
{
    auto status = kernel_ScriptVerifyStatus::kernel_SCRIPT_VERIFY_OK;
    bench.run([&] {
        verify_script(
            ScriptPubkey{hex_string_to_char_vec("001491b24bf9f5288532960ac687abb035127b1d28a5")},
            1,  // amount
            Transaction{hex_string_to_char_vec("0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01010000000000000016001491b24bf9f5288532960ac687abb035127b1d28a50248304402201e7216e5ccb3b61d46946ec6cc7e8c4e0117d13ac2fd4b152197e4805191c74202203e9903e33e84d9ee1dd13fb057afb7ccfb47006c23f6a067185efbc9dd780fc50101410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b800000000")},
            {},
            0,
            kernel_SCRIPT_FLAGS_VERIFY_P2SH | kernel_SCRIPT_FLAGS_VERIFY_WITNESS,
            status);
        assert(status == kernel_SCRIPT_VERIFY_OK);
    });
}



BENCHMARK(VerifyScriptKernelApiBench, benchmark::PriorityLevel::HIGH);















