extern "C" {
#include "include/hello.h"
}
#include <gtest/gtest.h>

TEST(test1, helloTest) {
    int ret = hello();
    ASSERT_EQ(ret, 42);
}
