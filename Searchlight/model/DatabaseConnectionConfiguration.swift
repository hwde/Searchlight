//
//  DatabaseConnectionConfiguration.swift
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

// SSH Tunnel Configuration
struct SSHTunnelConfiguration: Codable, Hashable {
    let enabled: Bool
    let host: String
    let port: Int
    let user: String
    let keyPath: String
    let keyBookmarkData: Data?  // Security-scoped bookmark for persistent file access
}

// TLS mode for the Postgres connection, modelled after libpq's sslmode.
enum SSLMode: String, Codable, CaseIterable, Hashable {
    // No TLS at all; credentials and data travel in plain text.
    case disable
    // TLS without certificate verification (encrypts, but does not authenticate the server).
    // Needed for local port forwards (e.g. 127.0.0.1) where the certificate cannot match the host.
    case require
    // TLS with full verification of the certificate chain and the server hostname.
    case verifyFull = "verify-full"

    var displayName: String {
        switch self {
        case .disable: return "Disable"
        case .require: return "Require (no verification)"
        case .verifyFull: return "Verify full"
        }
    }
}

// Struct to wrap the database configuration in an API abstract way.
// The password is deliberately not part of the encoded representation (it is written as ""):
// FavoritesStore keeps it in the Keychain.
struct DatabaseConnectionConfiguration: Codable, Identifiable, Hashable {
    
    // Id = name
    var id: String { name }
    
    // The name of the configuration provided by the user. This is just used to save on favorites, and not on the actual connection
    let name: String
    
    // Database host (without schema or protocol)
    let host: String
    
    // Database port
    var port: Int = 5432
    
    // The name of the database schema
    let database: String
    
    // Database user
    let user: String
    
    // Database password
    let password: String
    
    // TLS mode used for the connection
    let sslMode: SSLMode
    
    // Whether the current connection is a favorited connection
    let favorited: Bool

    // SSH Tunnel configuration (optional)
    let sshTunnel: SSHTunnelConfiguration?

    // TODO: this is a bit of a hack, and can be better implemented by moving the connection out of the DatabaseConnection View
    // This is used as an internal shortcut to notify the DatabaseConnectionView to try to connect right away.
    var connectRightAway: Bool = false

    // Visual customization for favorites
    let favoriteColor: String?     // Hex color string (e.g., "#0000FF")
    let favoriteIcon: String?      // SF Symbol name (e.g., "star.fill")

    init(name: String, host: String, port: Int = 5432, database: String, user: String, password: String, sslMode: SSLMode, favorited: Bool, sshTunnel: SSHTunnelConfiguration?, connectRightAway: Bool = false, favoriteColor: String? = nil, favoriteIcon: String? = nil) {
        self.name = name
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.sslMode = sslMode
        self.favorited = favorited
        self.sshTunnel = sshTunnel
        self.connectRightAway = connectRightAway
        self.favoriteColor = favoriteColor
        self.favoriteIcon = favoriteIcon
    }
}

extension DatabaseConnectionConfiguration {
    private enum CodingKeys: String, CodingKey {
        case name, host, port, database, user, sslMode, favorited, sshTunnel, favoriteColor, favoriteIcon
        // Keys of versions <= 0.10. Read for migration; still written with harmless values (see encode)
        case password, ssl, connectRightAway
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decode(Int.self, forKey: .port)
        database = try container.decode(String.self, forKey: .database)
        user = try container.decode(String.self, forKey: .user)
        // New data writes this key as "" for downgrade compatibility (see encode). Only a non-empty value is a
        // legacy plain-text password (versions <= 0.10), which FavoritesStore moves into the Keychain.
        password = try container.decodeIfPresent(String.self, forKey: .password) ?? ""
        if let mode = try container.decodeIfPresent(SSLMode.self, forKey: .sslMode) {
            sslMode = mode
        } else {
            // Older versions only had a boolean. "true" meant TLS without certificate verification,
            // so it maps to .require to keep the exact previous behaviour.
            let legacySSL = try container.decode(Bool.self, forKey: .ssl)
            sslMode = legacySSL ? .require : .disable
        }
        favorited = try container.decode(Bool.self, forKey: .favorited)
        sshTunnel = try container.decodeIfPresent(SSHTunnelConfiguration.self, forKey: .sshTunnel)
        connectRightAway = false
        favoriteColor = try container.decodeIfPresent(String.self, forKey: .favoriteColor)
        favoriteIcon = try container.decodeIfPresent(String.self, forKey: .favoriteIcon)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode(host, forKey: .host)
        try container.encode(port, forKey: .port)
        try container.encode(database, forKey: .database)
        try container.encode(user, forKey: .user)
        try container.encode(sslMode, forKey: .sslMode)
        try container.encode(favorited, forKey: .favorited)
        try container.encodeIfPresent(sshTunnel, forKey: .sshTunnel)
        try container.encodeIfPresent(favoriteColor, forKey: .favoriteColor)
        try container.encodeIfPresent(favoriteIcon, forKey: .favoriteIcon)
        // The real password is never encoded. The legacy keys are written so that versions <= 0.10, whose
        // decoder requires them, can still read the list after a downgrade instead of silently dropping
        // (and on the next save overwriting) all favorites. An empty password there means "no password".
        try container.encode("", forKey: .password)
        try container.encode(sslMode != .disable, forKey: .ssl)
        try container.encode(false, forKey: .connectRightAway)
    }

    // Returns a copy with a different SSL mode (used to restore modes a downgraded version dropped)
    func withSSLMode(_ newMode: SSLMode) -> Self {
        DatabaseConnectionConfiguration(name: name, host: host, port: port, database: database, user: user, password: password, sslMode: newMode, favorited: favorited, sshTunnel: sshTunnel, connectRightAway: connectRightAway, favoriteColor: favoriteColor, favoriteIcon: favoriteIcon)
    }

    // Returns a copy with a different password (used when loading the password from the Keychain)
    func withPassword(_ newPassword: String) -> Self {
        DatabaseConnectionConfiguration(name: name, host: host, port: port, database: database, user: user, password: newPassword, sslMode: sslMode, favorited: favorited, sshTunnel: sshTunnel, connectRightAway: connectRightAway, favoriteColor: favoriteColor, favoriteIcon: favoriteIcon)
    }
}

// Creates a copy of the struct, overriding the database name with the one passed as argument.
// This is to help with the database change funcionality, where we need to create a new connection.
extension DatabaseConnectionConfiguration {
    func copyWithDatabaseChangedTo(database newDatabase: String) -> Self {
        return DatabaseConnectionConfiguration(name: id, host: host, port: port, database: newDatabase, user: user, password: password, sslMode: sslMode, favorited: favorited, sshTunnel: sshTunnel, connectRightAway: connectRightAway, favoriteColor: favoriteColor, favoriteIcon: favoriteIcon)
    }
}

class DatabaseConnectionConfigurationWrapper: ObservableObject, Equatable {
    @Published var configuration: DatabaseConnectionConfiguration?
    
    init(configuration: DatabaseConnectionConfiguration) {
        self.configuration = configuration
    }
    
    static func == (lhs: DatabaseConnectionConfigurationWrapper, rhs: DatabaseConnectionConfigurationWrapper) -> Bool {
        return lhs.configuration == rhs.configuration
    }
}
