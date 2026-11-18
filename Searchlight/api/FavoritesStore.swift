//
//  FavoritesStore.swift
//  Searchlight
//
//  Created by Ravel Antunes on 9/25/24.
//
//  Copyright (c) 2024 Ravel Antunes
//
//  This software is licensed under the MIT License.
//  You may obtain a copy of the License at https://opensource.org/licenses/MIT
//

import Foundation
import SwiftUI

enum FavoritesStoreError: Error, LocalizedError {
    case storedFavoritesUnreadable(String)

    var errorDescription: String? {
        switch self {
        case .storedFavoritesUnreadable(let message):
            return "The saved favorites could not be read, so they were not changed: \(message)"
        }
    }
}

// Handles interaction with UserDefaults as the mechanism to store favorite lists information.
// Passwords are not stored in UserDefaults but in the Keychain (see KeychainStore).
class FavoritesStore: ObservableObject {
    
    static let shared = FavoritesStore()
    let suiteName = "com.searchlight.Searchlight.favorites"
    private let FavoriteDatabasesListKey: String = "favoriteDatabasesList"
    // SSL mode per favorite name, kept outside the list: versions <= 0.10 rewrite the list after a downgrade
    // and drop sslMode, which would otherwise turn "verify-full" into "require" after the next upgrade.
    private let FavoriteSSLModesKey: String = "favoriteSSLModes"
    
    @Published var favorites = [DatabaseConnectionConfiguration]()

    // Problem from the last refresh that the user needs to see (unreadable list or Keychain items), or nil
    @Published private(set) var loadProblem: String?

    init() {
        refresh()
    }

    // Reloads the published list, including passwords from the Keychain (one read per favorite)
    private func refresh() {
        let stored: [DatabaseConnectionConfiguration]
        do {
            stored = try storedFavorites()
        } catch {
            print("Failed to load favorites: \(error.localizedDescription)")
            favorites = []
            loadProblem = error.localizedDescription
            return
        }

        // On failure the plain-text passwords stay in use and in UserDefaults; the migration is retried on the
        // next refresh, and saving/removing refuses to rewrite the list until it succeeds (requireMigrated).
        let migrated: [DatabaseConnectionConfiguration]
        var problems = [String]()
        do {
            migrated = try requireMigrated(stored)
        } catch {
            print("Failed to migrate passwords to the Keychain: \(error.localizedDescription)")
            problems.append("Saved passwords could not be moved into the Keychain (\(error.localizedDescription)). Saving or deleting favorites is blocked until this works.")
            migrated = stored
        }

        var unreadable = Set<String>()
        let loaded = migrated.map { config -> DatabaseConnectionConfiguration in
            // Still has a plain-text password: migration did not complete, keep using it
            if !config.password.isEmpty {
                return config
            }
            do {
                return config.withPassword(try KeychainStore.password(account: config.name) ?? "")
            } catch {
                print("Failed to read password for favorite \(config.name): \(error.localizedDescription)")
                unreadable.insert(config.name)
                return config
            }
        }
        favorites = loaded.sorted(by: { $0.name < $1.name })
        if !unreadable.isEmpty {
            problems.append("The Keychain password of \(unreadable.sorted().map { "\"\($0)\"" }.joined(separator: ", ")) could not be read. Connections will fail; allow Searchlight to access the Keychain item and restart it, or enter the password again.")
        }
        loadProblem = problems.isEmpty ? nil : problems.joined(separator: "\n")
    }
    
    // Saves the favorite. The password goes to the Keychain first; if that fails nothing is written,
    // so a password never silently ends up in plain text.
    // passwordEdited: whether the user changed the password field. An unchanged empty field leaves the stored
    // password alone (it may simply not have been readable); only a field the user cleared deletes it.
    func saveFavorite(databaseConnectionConfiguration: DatabaseConnectionConfiguration, passwordEdited: Bool) throws {
        // Refresh also when a later step fails: the migration may already have rewritten the stored data.
        // Not when the migration itself failed: nothing changed, and retrying it at once would only show
        // the Keychain access dialog again right after the user denied it.
        var migrated = false
        defer { if migrated { refresh() } }
        let name = databaseConnectionConfiguration.name
        var currentList = try requireMigrated(try storedFavorites())
        migrated = true

        if !databaseConnectionConfiguration.password.isEmpty {
            try KeychainStore.setPassword(databaseConnectionConfiguration.password, account: name)
        } else if passwordEdited {
            try KeychainStore.deletePassword(account: name)
        }

        // Tries to find existing connection with the same name. If it exists, just replace it
        currentList.removeAll(where: { $0.name == name })
        currentList.append(databaseConnectionConfiguration)

        try writeFavorites(currentList)
    }
    
    func saveLastSelectedDatabaseName(databaseConnectionConfigurationName: String) {
        UserDefaults.standard.set(databaseConnectionConfigurationName, forKey: "lastSelectedDatabase")
    }
    
    // Deletes the Keychain item first: if that fails the favorite stays, so the deletion can be retried
    // and no password is left behind without a favorite pointing to it.
    func removeFavorite(databaseConnectionConfiguration: DatabaseConnectionConfiguration) throws {
        // Same rule as in saveFavorite: refresh unless the migration itself failed
        var migrated = false
        defer { if migrated { refresh() } }
        let name = databaseConnectionConfiguration.name
        let currentList = try requireMigrated(try storedFavorites())
        migrated = true
        try KeychainStore.deletePassword(account: name)
        try writeFavorites(currentList.filter { $0.name != name })
    }

    // Decodes the stored list without touching the Keychain. Throws if the data exists but cannot be decoded,
    // so callers never overwrite favorites they could not read.
    private func storedFavorites() throws -> [DatabaseConnectionConfiguration] {
        guard let data = UserDefaults.standard.data(forKey: FavoriteDatabasesListKey) else {
            return []
        }
        let list: [DatabaseConnectionConfiguration]
        let probes: [SSLModeProbe]
        do {
            list = try JSONDecoder().decode([DatabaseConnectionConfiguration].self, from: data)
            probes = try JSONDecoder().decode([SSLModeProbe].self, from: data)
        } catch {
            throw FavoritesStoreError.storedFavoritesUnreadable(error.localizedDescription)
        }

        // Entries without sslMode were written by an older version (initial upgrade, or a save after a downgrade).
        // Their legacy ssl=true maps to .require; restore .verifyFull if this version had stored it for the name.
        let savedModes = UserDefaults.standard.dictionary(forKey: FavoriteSSLModesKey) as? [String: String] ?? [:]
        return zip(list, probes).map { config, probe in
            guard probe.sslMode == nil, config.sslMode == .require,
                  savedModes[config.name] == SSLMode.verifyFull.rawValue else {
                return config
            }
            return config.withSSLMode(.verifyFull)
        }
    }

    private struct SSLModeProbe: Decodable {
        let sslMode: SSLMode?
    }

    // Migration: versions <= 0.10 stored passwords in plain text in UserDefaults. Moves them into the Keychain
    // and rewrites the list without them, returning the list with passwords cleared. Throws if a Keychain write
    // fails; nothing is rewritten then, because writing the list would drop the plain-text passwords.
    private func requireMigrated(_ list: [DatabaseConnectionConfiguration]) throws -> [DatabaseConnectionConfiguration] {
        let legacy = list.filter { !$0.password.isEmpty }
        guard !legacy.isEmpty else { return list }
        for config in legacy {
            try KeychainStore.setPassword(config.password, account: config.name)
        }
        try writeFavorites(list)
        print("Migrated \(legacy.count) password(s) from UserDefaults to the Keychain")
        return list.map { $0.withPassword("") }
    }

    // Encodes the list without passwords (DatabaseConnectionConfiguration.encode skips them)
    private func writeFavorites(_ list: [DatabaseConnectionConfiguration]) throws {
        let encoded = try JSONEncoder().encode(list)
        UserDefaults.standard.set(encoded, forKey: FavoriteDatabasesListKey)
        UserDefaults.standard.set(Dictionary(list.map { ($0.name, $0.sslMode.rawValue) }, uniquingKeysWith: { _, last in last }), forKey: FavoriteSSLModesKey)
        UserDefaults.standard.synchronize()
    }
    
    func loadLastSelectedDatabase() -> String? {
        UserDefaults.standard.string(forKey: "lastSelectedDatabase")
    }
}
