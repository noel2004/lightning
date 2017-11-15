#include <stdio.h>
#include "gtest/gtest.h"
#include "include/lnchannel_api.h"

GTEST_API_ int main(int argc, char **argv) {
    printf("Running main() from gtest_main.cc\n");

    auto pcore = LNAPI_init();
    auto pws = LNAPI_assign_workspace(pcore);

    testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();

    return ret;
}