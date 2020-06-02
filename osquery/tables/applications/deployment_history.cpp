/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem/path.hpp>

#include <osquery/core.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/utils/conversions/split.h"
#include "osquery/filesystem/fileops.h"

namespace fs = boost::filesystem;

namespace osquery {
	namespace tables {

		fs::path kDeploymentHistory = "/opt/oneops/deployment_history";

		QueryData parseDeploymentHistory(const std::string& content) {
			QueryData results;

			for (const auto& _line : osquery::split(content, "\n")) {
				auto line = split(_line);
				if (line.size() == 0 || boost::starts_with(line[0], "#")) {
					continue;
				}

				Row r;
				r["component"] = line[0];
				if (line.size() > 1) {
					r["start"] = line[1];
					if (line.size() > 2) {
						r["end"] = line[2];
					}
					if (line.size() > 3) {
						r["deployer"] = line[3];
					}
				}
				results.push_back(r);
			}

			return results;
		}

		QueryData genDeploymentHistory(QueryContext& context) {
			std::string content;
			QueryData qres = {};

			if (readFile(kDeploymentHistory, content).ok()) {
				qres = parseDeploymentHistory(content);
			}

			return qres;
		}
	}
}
