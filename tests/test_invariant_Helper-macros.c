#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "archive/Helper-macros.c"

START_TEST(test_qmemcpy_bounds_safety)
{
    // Invariant: QMEMCPY must not write beyond the destination buffer bounds.
    // We test by placing a canary after the destination buffer and verifying
    // it remains intact after copy operations with various 'n' values.

    size_t test_sizes[] = {
        0,      // boundary: zero-length copy
        4,      // valid: small copy within bounds
        16,     // valid: exact buffer size
    };
    int num_tests = sizeof(test_sizes) / sizeof(test_sizes[0]);

    for (int i = 0; i < num_tests; i++) {
        size_t n = test_sizes[i];
        size_t buf_size = 16;
        unsigned char canary = 0xDE;

        // Allocate destination with extra byte as canary
        unsigned char *dst = (unsigned char *)calloc(buf_size + 1, 1);
        ck_assert_ptr_nonnull(dst);
        dst[buf_size] = canary;

        // Source buffer filled with known pattern
        unsigned char *src = (unsigned char *)malloc(buf_size);
        ck_assert_ptr_nonnull(src);
        memset(src, 0xAB, buf_size);

        // Only perform copy if n fits in destination
        if (n <= buf_size) {
            int counter = 0;
            QMEMCPY(counter, src, dst, (int)n);
            // Verify canary is intact - no out-of-bounds write
            ck_assert_msg(dst[buf_size] == canary,
                "QMEMCPY overwrote past destination buffer with n=%zu", n);
        }

        free(src);
        free(dst);
    }
}
END_TEST

START_TEST(test_qmemcpy_overflow_attempt)
{
    // Invariant: If n exceeds destination capacity, memory beyond buffer must not be corrupted.
    // This simulates an attacker-controlled 'n' larger than the destination.
    size_t buf_size = 8;
    size_t adversarial_n = 64; // attacker tries to copy 64 bytes into 8-byte buffer

    unsigned char *dst = (unsigned char *)calloc(adversarial_n + 1, 1);
    ck_assert_ptr_nonnull(dst);
    unsigned char canary = 0xFE;
    dst[buf_size] = canary; // canary at logical end of "intended" buffer

    unsigned char *src = (unsigned char *)malloc(adversarial_n);
    ck_assert_ptr_nonnull(src);
    memset(src, 0xCC, adversarial_n);

    int counter = 0;
    // Perform the copy with adversarial n - the macro will write beyond buf_size
    QMEMCPY(counter, src, dst, (int)adversarial_n);

    // This SHOULD fail if QMEMCPY doesn't validate bounds - detecting the vulnerability
    ck_assert_msg(dst[buf_size] == canary,
        "QMEMCPY wrote beyond intended destination bounds with adversarial n=%zu", adversarial_n);

    free(src);
    free(dst);
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_qmemcpy_bounds_safety);
    tcase_add_test(tc_core, test_qmemcpy_overflow_attempt);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}