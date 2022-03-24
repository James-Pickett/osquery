// osquery/tables/system/darwin/bluetooth_info.mm

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#import <AppKit/NSDocument.h>
#import <Foundation/Foundation.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

@interface SPDocument : NSDocument {
}
- (id)reportForDataType:(id)arg1;
@end

namespace osquery {
namespace tables {

QueryData genBluetoothInfo(QueryContext& context) {
  Row r;
  QueryData results;

  // BEWARE: Because of the dynamic nature of the calls in this function, we
  // must be careful to properly clean up the memory. Any future modifications
  // to this function should attempt to ensure there are no leaks.
  CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
      kCFAllocatorDefault,
      CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
      kCFURLPOSIXPathStyle,
      true);

  if (bundle_url == nullptr) {
    LOG(ERROR) << "Error parsing SPSupport bundle URL";
    return results;
  }

  CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
  CFRelease(bundle_url);
  if (bundle == nullptr) {
    LOG(ERROR) << "Error opening SPSupport bundle";
    return results;
  }

  CFBundleLoadExecutable(bundle);

  std::function<void()> cleanup = [&]() {
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

  id cls = NSClassFromString(@"SPDocument");
  if (cls == nullptr) {
    LOG(ERROR) << "Could not load SPDocument class";
    cleanup();

    return results;
  }

  SEL sel = @selector(new);
  if (![cls respondsToSelector:sel]) {
    LOG(ERROR) << "SPDocument does not respond to new selector";
    cleanup();

    return results;
  }

  id document = [cls performSelector:sel];
  if (document == nullptr) {
    LOG(ERROR) << "[SPDocument new] returned null";
    cleanup();

    return results;
  }

  #pragma clang diagnostic pop

  cleanup = [&]() {
    CFRelease((__bridge CFTypeRef)document);
    CFBundleUnloadExecutable(bundle);
    CFRelease(bundle);
  };

  NSDictionary* report = [[[document reportForDataType:@"SPBluetoothDataType"]
      objectForKey:@"_items"] lastObject];
  NSDictionary* data = [report objectForKey:@"controller_properties"];

  if (data == nullptr) {
    cleanup();
    return results;
  }

  NSString* state = [data objectForKey:@"controller_state"];
  NSString* discoverable = [data objectForKey:@"controller_discoverable"];
  NSString* address = [data objectForKey:@"controller_address"];
  NSString* chipset = [data objectForKey:@"controller_chipset"];
  NSString* vendorId = [data objectForKey:@"controller_vendorID"];
  NSString* firmwareVersion = [data objectForKey:@"controller_firmwareVersion"];
  NSString* supportedServices =
      [data objectForKey:@"controller_supportedServices"];

  if (state) {
    if ([state isEqualToString:@"attrib_on"]) {
      r["state"] = INTEGER(1);
    } else {
      r["state"] = INTEGER(0);
    }
  }

  if (discoverable) {
    if ([discoverable isEqualToString:@"attrib_on"]) {
      r["discoverable"] = INTEGER(1);
    } else {
      r["discoverable"] = INTEGER(0);
    }
  }

  if (address) {
    r["address"] = [address UTF8String];
  }

  if (chipset) {
    r["chipset"] = [chipset UTF8String];
  }

  if (vendorId) {
    r["vendor_id"] = [vendorId UTF8String];
  }

  if (firmwareVersion) {
    r["firmware_version"] = [firmwareVersion UTF8String];
  }

  if (supportedServices) {
    r["supported_services"] = [supportedServices UTF8String];
  }

  cleanup();
  results.push_back(r);
  return results;
}

} // namespace tables
} // namespace osquery
