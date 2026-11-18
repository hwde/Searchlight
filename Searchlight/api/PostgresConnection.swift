//
//  PostgresConnection.swift
//  Searchlight
//
//  Created by Ravel Antunes on 9/28/24.
//
//  Copyright (c) 2024 Ravel Antunes
//
//  This software is licensed under the MIT License.
//  You may obtain a copy of the License at https://opensource.org/licenses/MIT
//

import Foundation
import PostgresKit
import CryptoKit

// This class was originally named PostgresConnectionManager (since it is managing a pool of connections) but I renamed to PostgresConnection to make the name less redundant with ConnectionsManager.
// Ideally this class is all we would need, but since changing databases requires to create new connection (and the PostgresConnectionSource requires the database as an argument) the ConnectionsManager
// helps handling multiple PostgresConnection for different databases.
class PostgresConnection {

    private let configuration: DatabaseConnectionConfiguration
    private let eventLoopGroup: MultiThreadedEventLoopGroup
    private let connectionPool: EventLoopGroupConnectionPool<PostgresConnectionSource>
    private var sshTunnelManager: SSHTunnelManager?
    private var isClosed = false

    // The local port used by the SSH tunnel, or nil if no tunnel is active
    var tunnelLocalPort: Int? {
        return sshTunnelManager?.localPort
    }

    init(configuration: DatabaseConnectionConfiguration) async throws {
        self.configuration = configuration

        let usesTunnel = configuration.sshTunnel?.enabled == true

        // Through an SSH tunnel the TLS connection goes to 127.0.0.1. A hostname can still be verified via
        // SNI/tlsServerName, but an IP address cannot be passed that way, so NIOSSL would check the certificate
        // against 127.0.0.1 instead of the database. Refuse instead of verifying the wrong identity.
        if configuration.sslMode == .verifyFull && usesTunnel && PostgresConnection.isIPAddress(configuration.host) {
            throw NSError(domain: "postgres-mac-client", code: 1, userInfo: [NSLocalizedDescriptionKey: "SSL Mode \"Verify full\" through an SSH tunnel needs the database host as a hostname, not an IP address (\(configuration.host)). Use the hostname from the server certificate, or choose \"Require\"."])
        }

        // Build the TLS settings before starting the tunnel, so a failure here cannot leave an ssh process behind
        let tls: PostgresNIO.PostgresConnection.Configuration.TLS
        switch configuration.sslMode {
        case .disable:
            tls = .disable
        case .require:
            // Encrypts, but does not authenticate the server (libpq sslmode=require).
            // Meant for local port forwards where the certificate cannot match 127.0.0.1.
            var tlsConfig = TLSConfiguration.makeClientConfiguration()
            tlsConfig.certificateVerification = .none
            tls = .require(try NIOSSLContext(configuration: tlsConfig))
        case .verifyFull:
            // Verifies the certificate chain against the system trust store and the hostname
            // (or, for an IP address host, the IP against the certificate's IP SANs).
            var tlsConfig = TLSConfiguration.makeClientConfiguration()
            tlsConfig.certificateVerification = .fullVerification
            tls = .require(try NIOSSLContext(configuration: tlsConfig))
        }

        // Establish SSH tunnel if configured
        let connectionHost: String
        let connectionPort: Int

        if let sshConfig = configuration.sshTunnel, sshConfig.enabled {
            print("SSH tunnel enabled, establishing tunnel...")
            let tunnelManager = SSHTunnelManager(
                sshConfig: sshConfig,
                remoteHost: configuration.host,
                remotePort: configuration.port
            )
            try await tunnelManager.establishTunnel()
            self.sshTunnelManager = tunnelManager

            // Connect to localhost using the tunnel's local port
            connectionHost = "127.0.0.1"
            connectionPort = tunnelManager.localPort
            print("SSH tunnel established on localhost:\(connectionPort)")
        } else {
            // Direct connection without SSH tunnel
            connectionHost = configuration.host
            connectionPort = configuration.port
        }

        // Map our internal config struct into the NIO config
        var postgresNIOSqlConfiguration = SQLPostgresConfiguration(
            hostname: connectionHost,
            port: connectionPort,
            username: configuration.user,
            password: configuration.password,
            database: configuration.database,
            tls: tls
        )
        // Through an SSH tunnel we connect to 127.0.0.1, but the certificate belongs to the real database host,
        // so SNI and hostname verification must use that name. (IP hosts with verify-full are rejected above.)
        if usesTunnel && !PostgresConnection.isIPAddress(configuration.host) {
            postgresNIOSqlConfiguration.coreConfiguration.options.tlsServerName = configuration.host
        }

        // Created last: nothing above can fail after this point, so the group cannot leak from a failed init
        eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        let connectionSource = PostgresConnectionSource(sqlConfiguration: postgresNIOSqlConfiguration)
        connectionPool = EventLoopGroupConnectionPool(
            source: connectionSource,
            maxConnectionsPerEventLoop: 2,
            on: eventLoopGroup
        )
    }

    private static func isIPAddress(_ host: String) -> Bool {
        // Accept bracketed IPv6 ("[::1]") and zone IDs ("fe80::1%en0") as IP addresses too
        var address = host
        if address.hasPrefix("[") && address.hasSuffix("]") {
            address = String(address.dropFirst().dropLast())
        }
        if let zone = address.firstIndex(of: "%") {
            address = String(address[..<zone])
        }
        var ipv4 = in_addr()
        var ipv6 = in6_addr()
        return inet_pton(AF_INET, address, &ipv4) == 1 || inet_pton(AF_INET6, address, &ipv6) == 1
    }

    /// Closes the connection pool and event loop group.
    /// This is idempotent so it can be safely called multiple times.
    func close() async {
        guard !isClosed else { return }
        isClosed = true

        // Close SSH tunnel if established
        if let tunnel = sshTunnelManager {
            try? await tunnel.closeTunnel()
        }

        await withCheckedContinuation { continuation in
            connectionPool.shutdownGracefully { error in
                if let error {
                    print("Failed to shutdown connection pool: \(error)")
                }
                continuation.resume()
            }
        }

        do {
            try eventLoopGroup.syncShutdownGracefully()
        } catch {
            print("Failed to shutdown EventLoopGroup: \(error)")
        }
    }

    deinit {
        // Synchronous cleanup - cannot use async in deinit
        guard !isClosed else { return }

        // Note: sshTunnelManager will clean itself up in its own deinit

        // Best-effort synchronous shutdown of connection pool and event loop
        connectionPool.shutdownGracefully { error in
            if let error {
                print("Failed to shutdown connection pool in deinit: \(error)")
            }
        }

        try? eventLoopGroup.syncShutdownGracefully()
    }
    
    func testConnection() async throws {
        let testResult = try await query(query: "SELECT version()")
        let version = try testResult[0]["version"].decode((String).self)
        print("Version: \(version)")
    }
    
    func query(query: String) async throws -> [PostgresRandomAccessRow] {
        do {
            return try await withCheckedThrowingContinuation { continuation in
                connectionPool.withConnection { connection -> EventLoopFuture<PostgresQueryResult> in
                    return connection.query(query)
                }.whenComplete { result in
                    switch result {
                    case .success(let queryResult):
                        continuation.resume(returning: queryResult.rows.map { $0.makeRandomAccess() })
                    case .failure(let error):
                        print("TODO: error handling")
                        continuation.resume(throwing: error)
                    }
                }
            }
        } catch let error as PSQLError {
            // TODO create an Error implementation
            switch error.code {
            case .sslUnsupported:
                throw NSError(domain: "postgres-mac-client", code: 1, userInfo: [NSLocalizedDescriptionKey: "The server refused SSL. This can be a server without SSL support, but also an attacker between you and the server. Only set SSL Mode to \"Disable\" if you trust the network path: the password and all data are then sent unencrypted."])
            case .server:
                throw NSError(domain: "postgres-mac-client", code: 1, userInfo: [NSLocalizedDescriptionKey: error.serverInfo![.message]!])
            case .connectionError, .failedToAddSSLHandler:
                // PostgresNIO wraps TLS handshake and certificate failures as connection errors too
                if let underlying = error.underlying,
                   underlying is NIOSSLError || underlying is BoringSSLError || underlying is NIOSSLExtraError {
                    let hint = configuration.sslMode == .verifyFull
                        ? " With \"\(SSLMode.verifyFull.displayName)\" the server certificate must be trusted by macOS and match the host name; for a self-signed or private CA certificate choose \"\(SSLMode.require.displayName)\"."
                        : ""
                    throw NSError(domain: "postgres-mac-client", code: 1, userInfo: [NSLocalizedDescriptionKey: "TLS handshake failed with SSL Mode \"\(configuration.sslMode.displayName)\": \(underlying).\(hint)"])
                }
                if error.code == .failedToAddSSLHandler {
                    throw NSError(domain: "postgres-mac-client", code: 1, userInfo: [NSLocalizedDescriptionKey: "TLS could not be set up with SSL Mode \"\(configuration.sslMode.displayName)\": \(error.underlying.map { String(describing: $0) } ?? "unknown error")."])
                }
                throw NSError(domain: "postgres-mac-client", code: 1, userInfo: [NSLocalizedDescriptionKey: "Check your hostname and port."])
            default:
                throw error
            }
        } catch let postgresError as PostgresNIO.PostgresError {
            switch postgresError {
            case .server(let serverError):
                serverError.fields.forEach { print($0) }
                
                let errorColumn = serverError.fields[PostgresMessage.Error.Field.columnName]
                let message = serverError.fields[PostgresMessage.Error.Field.message]
                
                if let message = message {
                    throw SearchlightAPIError(description: message, columnName: errorColumn)
                }
            default:
                throw postgresError
            }
                    
            throw postgresError
        } catch {
            // TODO: parse error
            throw error
        }
    }
}
