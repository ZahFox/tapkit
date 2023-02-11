#include <CUnit/Basic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tapkit.h"

/* printf/fprintf calls in this tester will NOT go to file. */
#undef printf
#undef fprintf

/*
 * The suite initialization function.
 */
int init_suite(void) {
  unlink("TEST_STDOUT");
  unlink("TEST_STDERR");
  return 0;
}

/*
 * The suite cleanup function.
 */
int clean_suite(void) { return 0; }

void simple_sample_test(void) {
  CU_ASSERT(0 == 0);
  CU_ASSERT(1 == 10);
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int cunittester() {
  CU_pSuite pSuite = NULL;
  CU_pSuite pSuite2 = NULL;

  /* initialize the CUnit test registry */
  if (CUE_SUCCESS != CU_initialize_registry()) return CU_get_error();

  /* add a suite to the registry */
  pSuite = CU_add_suite("Suite_1", init_suite, clean_suite);
  if (NULL == pSuite) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Add tests to the Suite #1 */
  if (NULL == CU_add_test(pSuite, "Simple Test #1", simple_sample_test)) {
    CU_cleanup_registry();
    return CU_get_error();
  }

  /* Run all tests using the CUnit Basic interface */
  CU_basic_set_mode(CU_BRM_VERBOSE);
  CU_basic_run_tests();
  CU_cleanup_registry();
  return CU_get_error();
}