/*
 * Copyright (c) 2024, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package psiphon

import (
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIPLookup provides client-side GeoIP lookup functionality using a
// MaxMind GeoLite2 or GeoIP2 Country database.
type GeoIPLookup struct {
	reader *maxminddb.Reader
	mutex  sync.RWMutex
}

// geoIPCountryRecord is the struct for decoding country data from MaxMind database.
// The struct tags match the MaxMind database field names.
type geoIPCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

var (
	geoIPInstance *GeoIPLookup
	geoIPOnce     sync.Once
	geoIPInitErr  error
)

// InitGeoIP initializes the global GeoIP lookup instance with the specified
// MaxMind database file. This should be called once during startup if
// GeoIPDatabasePath is configured. Thread-safe.
func InitGeoIP(databasePath string) error {
	geoIPOnce.Do(func() {
		if databasePath == "" {
			return
		}

		reader, err := maxminddb.Open(databasePath)
		if err != nil {
			geoIPInitErr = err
			NoticeWarning("failed to open GeoIP database %s: %v", databasePath, err)
			return
		}

		geoIPInstance = &GeoIPLookup{
			reader: reader,
		}
		NoticeInfo("GeoIP database loaded: %s (type: %s, build: %d)",
			databasePath, reader.Metadata.DatabaseType, reader.Metadata.BuildEpoch)
	})
	return geoIPInitErr
}

// CloseGeoIP closes the global GeoIP database reader and releases resources.
// Should be called during shutdown.
func CloseGeoIP() {
	if geoIPInstance != nil {
		geoIPInstance.mutex.Lock()
		defer geoIPInstance.mutex.Unlock()
		if geoIPInstance.reader != nil {
			geoIPInstance.reader.Close()
			geoIPInstance.reader = nil
		}
	}
}

// LookupIPCountry returns the ISO 3166-1 alpha-2 country code for the given
// IP address (e.g., "IR", "CN", "US"). Returns an empty string if the lookup
// fails or GeoIP is not initialized.
func LookupIPCountry(ip net.IP) string {
	if geoIPInstance == nil {
		return ""
	}

	geoIPInstance.mutex.RLock()
	defer geoIPInstance.mutex.RUnlock()

	if geoIPInstance.reader == nil {
		return ""
	}

	var record geoIPCountryRecord
	err := geoIPInstance.reader.Lookup(ip, &record)
	if err != nil {
		return ""
	}

	return record.Country.ISOCode
}

// IsGeoIPAvailable returns true if GeoIP lookup is initialized and available.
func IsGeoIPAvailable() bool {
	return geoIPInstance != nil && geoIPInstance.reader != nil
}
