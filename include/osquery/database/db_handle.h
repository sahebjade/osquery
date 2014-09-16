// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest_prod.h>
#include <rocksdb/db.h>

#include "osquery/status.h"

namespace osquery {
namespace db {

/////////////////////////////////////////////////////////////////////////////
// Constants
/////////////////////////////////////////////////////////////////////////////

/// The default path of the RocksDB database on disk
extern const std::string kDBPath;

/**
 * @brief A const vector of column families in RocksDB
 *
 * RocksDB has a concept of "column families" which are kind of like tables
 * in other databases. kDomainds is populated with a list of all column
 * families. If a string exists in kDomains, it's a column family in the
 * database.
 */
extern const std::vector<std::string> kDomains;

/// The "domain" where the results of scheduled queries are stored
extern const std::string kQueries;

/// The "domain" where certain global configurations are stored
extern const std::string kConfigurations;

/////////////////////////////////////////////////////////////////////////////
// DBHandle RAII singleton
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief RAII singleton around RocksDB database access.
 *
 * Accessing RocksDB necessitates creating several pointers which must be
 * carefully memory managed. DBHandle offers you a singleton which takes
 * care of acquiring and releasing the relevant pointers and data structures
 * for you.
 */
class DBHandle {
 public:
  /**
   * @brief Destructor which takes care of deallocating all previously
   * allocated resources
   */
  ~DBHandle();

  /**
   * @brief The primary way to access the DBHandle singleton
   *
   * DBHandle::getInstance() provides access to the DBHandle singleton.
   *
   * @code{.cpp}
   *   auto db = DBHandle::getInstance();
   *   std::string value;
   *   auto status = db->Get("default", "foo", value);
   *   if (status.ok()) {
   *     assert(value == "bar");
   *   }
   * @endcode
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static std::shared_ptr<DBHandle> getInstance();

  /**
   * @brief Getter for the status of the operations required to open the
   * database
   *
   * @return an instance of osquery::Status which indicates the success or
   * failure of connecting to RocksDB
   */
  osquery::Status getStatus();

  /**
   * @brief Helper method which can be used to get a raw pointer to the
   * underlying RocksDB database handle
   *
   * You probably shouldn't use this. DBHandle::getDB() should only be used
   * when you're positive that it's the right thing to use.
   *
   * @return a pointer to the underlying RocksDB database handle
   */
  rocksdb::DB* getDB();

  /////////////////////////////////////////////////////////////////////////////
  // Data access methods
  /////////////////////////////////////////////////////////////////////////////

  /**
   * @brief Get data from the database
   *
   * @param domain the "domain" or "column family" that you'd like to retrieve
   * the data from
   * @param key the string key that you'd like to get
   * @param value a non-const string reference where the result of the
   * operation will be stored
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  osquery::Status Get(const std::string& domain,
                      const std::string& key,
                      std::string& value);

  /**
   * @brief Put data into the database
   *
   * @param domain the "domain" or "column family" that you'd like to insert
   * data into
   * @param key the string key that you'd like to put
   * @param value the data that you'd like to put into RocksDB
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  osquery::Status Put(const std::string& domain,
                      const std::string& key,
                      const std::string& value);

  /**
   * @brief Delete data from the database
   *
   * @param domain the "domain" or "column family" that you'd like to delete
   * data from
   * @param key the string key that you'd like to delete
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  osquery::Status Delete(const std::string& domain, const std::string& key);

  /**
   * @brief List the data in a "domain"
   *
   * @param domain the "domain" or "column family" that you'd like to list
   * data from
   * @param results a non-const reference to a vector which will be populated
   * with all of the keys from the supplied domain.
   *
   * @return an instance of osquery::Status indicating the success or failure
   * of the operation.
   */
  osquery::Status Scan(const std::string& domain,
                       std::vector<std::string>& results);

 private:
  /**
   * @brief Default constructor
   *
   * DBHandle's constructor takes care of properly connecting to RocksDB and
   * ensuring that all necessary column families are created. The resulting
   * database handle can then be accessed via DBHandle::getDB() and the
   * success of the connection can be determined by inspecting the resulting
   * status code via DBHandle::getStatus()
   */
  DBHandle();

  /**
   * @brief Internal only constructor used to create instances of DBHandle.
   *
   * This constructor allows you to specify a few more details about how you'd
   * like DBHandle to be used. This is only used internally, so you should
   * never actually use it.
   *
   * @param path the path to create/access the database
   * @param in_memory a boolean indicating wether or not the database should
   * be creating in memory or not.
   */
  DBHandle(std::string path, bool in_memory);

  /**
   * @brief A method which allows you to override the database path
   *
   * This should only be used by unit tests. Never use it in production code.
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static std::shared_ptr<DBHandle> getInstanceAtPath(const std::string& path);

  /**
   * @brief A method which gets you an in-memory RocksDB instance.
   *
   * This should only be used by unit tests. Never use it in production code.
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static std::shared_ptr<DBHandle> getInstanceInMemory();

  /**
   * @brief A method which allows you to configure various aspects of RocksDB
   * database options.
   *
   * This should only be used by unit tests. Never use it in production code.
   *
   * @param path the path to create/access the database
   * @param in_memory a boolean indicating wether or not the database should
   * be creating in memory or not.
   *
   * @return a shared pointer to an instance of DBHandle
   */
  static std::shared_ptr<DBHandle> getInstance(const std::string& path,
                                               bool in_memory);

  /**
   * @brief Private helper around accessing the column family handle for a
   * specific column family, based on it's name
   */
  rocksdb::ColumnFamilyHandle* getHandleForColumnFamily(const std::string& cf);

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Private members
  /////////////////////////////////////////////////////////////////////////////

  /// The database handle
  rocksdb::DB* db_;

  /// The status code that is generated while attempting to connect to RocksDB
  rocksdb::Status status_;

  /// Column family descriptors which are used to connect to RocksDB
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families_;

  /// A vector of pointers to column family handles
  std::vector<rocksdb::ColumnFamilyHandle*> handles_;

  /// The RocksDB connection options that are used to connect to RocksDB
  rocksdb::Options options_;

 private:
  /////////////////////////////////////////////////////////////////////////////
  // Unit tests which can access private members
  /////////////////////////////////////////////////////////////////////////////

  FRIEND_TEST(DBHandleTests, test_create_new_database_on_disk);
  FRIEND_TEST(DBHandleTests, test_singleton_on_disk);
  FRIEND_TEST(DBHandleTests, test_get_instance_in_memory);
  FRIEND_TEST(DBHandleTests, test_is_query_name_in_database);
  FRIEND_TEST(DBHandleTests, test_get_handle_for_column_family);
  FRIEND_TEST(DBHandleTests, test_get_stored_query_names);
  FRIEND_TEST(DBHandleTests, test_get_executions);
  FRIEND_TEST(DBHandleTests, test_get);
  FRIEND_TEST(DBHandleTests, test_put);
  FRIEND_TEST(DBHandleTests, test_delete);
  FRIEND_TEST(DBHandleTests, test_scan);

  FRIEND_TEST(QueryTests, test_add_and_get_current_results);
  FRIEND_TEST(QueryTests, test_is_query_name_in_database);
  FRIEND_TEST(QueryTests, test_get_stored_query_names);
  FRIEND_TEST(QueryTests, test_get_executions);
  FRIEND_TEST(QueryTests, test_get_current_results);
  FRIEND_TEST(QueryTests, test_get_historical_query_results);
  FRIEND_TEST(QueryTests, test_query_name_not_found_in_db);
};
}
}
