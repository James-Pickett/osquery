// tests/integration/tables/bluetooth_info.cpp

/**
  * Copyright (c) 2014-present, The osquery authors
  *
  * This source code is licensed as defined by the LICENSE file found in the
  * root directory of this source tree.
  *
  * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
  */

 // Sanity check integration test for location_services
 // Spec file: specs/darwin/bluetooth_info.table

 #include <osquery/tests/integration/tables/helper.h>

 namespace osquery {
 namespace table_tests {

 class bluetoothInfo : public testing::Test {
  protected:
   void SetUp() override {
     setUpEnvironment();
   }
 };

 TEST_F(bluetoothInfo, test_sanity) {
   auto const data = execute_query("select * from bluetooth_info");
   ASSERT_EQ(data.size(), 1ul);
   ValidationMap row_map = {
       {"state", IntType},
       {"discoverable", IntType},
       {"address", NormalType},
       {"vendor_id", NormalType},
       {"chipset", NormalType},
       {"firmware_version", NormalType},
       {"supported_services", NormalType},
   };
   validate_rows(data, row_map);
 }

 } // namespace table_tests
 } // namespace osquery
