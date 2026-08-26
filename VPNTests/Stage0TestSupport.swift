//
//  Stage0TestSupport.swift
//  VPNTests
//
//  Hermetic test-bundle helpers for the Stage 0 characterization baseline.
//

import Foundation

private final class Stage0TestBundleToken: NSObject {}

nonisolated enum Stage0TestResourceError: Error, CustomStringConvertible {
    case missingHostedApplicationBundle
    case missingLocalization(locale: String, available: [String])
    case missingLocalizedValue(key: String, locale: String)
    case missingFixture(name: String)
    case malformedFixture(name: String)
    case jsonStructureMismatch(name: String)
    case goldenTextMismatch(name: String)

    var description: String {
        switch self {
        case .missingHostedApplicationBundle:
            return "The VPNTests process is not hosted by the built VPN application bundle."
        case .missingLocalization(let locale, let available):
            return "The built VPN application is missing the \(locale) localization. Available localizations: \(available.sorted())."
        case .missingLocalizedValue(let key, let locale):
            return "The built VPN application is missing localization key \(key) for locale \(locale)."
        case .missingFixture(let name):
            return "The VPNTests bundle is missing the committed Stage 0 fixture \(name)."
        case .malformedFixture(let name):
            return "The committed Stage 0 fixture \(name) is not valid UTF-8."
        case .jsonStructureMismatch(let name):
            return "The produced JSON structure differs from the committed Stage 0 fixture \(name)."
        case .goldenTextMismatch(let name):
            return "The produced canonical text differs from the committed Stage 0 fixture \(name)."
        }
    }
}

nonisolated enum Stage0TestResources {
    static func requireLocalizations(
        for keys: [String],
        locales: [String] = ["en", "ru"]
    ) throws {
        let applicationBundle = Bundle.main
        guard applicationBundle.bundleURL.pathExtension == "app" else {
            throw Stage0TestResourceError.missingHostedApplicationBundle
        }

        for locale in locales {
            guard let localizationPath = applicationBundle.path(forResource: locale, ofType: "lproj"),
                  let localizationBundle = Bundle(path: localizationPath) else {
                throw Stage0TestResourceError.missingLocalization(
                    locale: locale,
                    available: applicationBundle.localizations
                )
            }

            for key in keys {
                let missingValue = "__STAGE0_MISSING_LOCALIZATION__\(locale)__\(key)__"
                let value = localizationBundle.localizedString(
                    forKey: key,
                    value: missingValue,
                    table: "Localizable"
                )
                guard value != missingValue else {
                    throw Stage0TestResourceError.missingLocalizedValue(key: key, locale: locale)
                }
            }
        }
    }

    static func fixtureData(named name: String, extension fileExtension: String = "json") throws -> Data {
        let testBundle = Bundle(for: Stage0TestBundleToken.self)
        guard let url = testBundle.url(forResource: name, withExtension: fileExtension) else {
            throw Stage0TestResourceError.missingFixture(name: "\(name).\(fileExtension)")
        }
        return try Data(contentsOf: url)
    }

    static func fixtureText(named name: String, extension fileExtension: String = "json") throws -> String {
        let data = try fixtureData(named: name, extension: fileExtension)
        guard var text = String(data: data, encoding: .utf8) else {
            throw Stage0TestResourceError.malformedFixture(name: "\(name).\(fileExtension)")
        }
        if text.hasSuffix("\n") {
            text.removeLast()
        }
        return text
    }

    static func requireGoldenJSON(_ actual: String, named name: String) throws {
        let expected = try fixtureText(named: name)
        guard let actualObject = try JSONSerialization.jsonObject(with: Data(actual.utf8)) as? NSObject,
              let expectedObject = try JSONSerialization.jsonObject(with: Data(expected.utf8)) as? NSObject,
              actualObject.isEqual(expectedObject) else {
            throw Stage0TestResourceError.jsonStructureMismatch(name: "\(name).json")
        }
        guard actual == expected else {
            throw Stage0TestResourceError.goldenTextMismatch(name: "\(name).json")
        }
    }
}
