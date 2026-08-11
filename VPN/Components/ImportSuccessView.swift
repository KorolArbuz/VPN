//
//  ImportSuccessView.swift
//  VPN
//
//  Created by Denis Chizhov on 11.08.2026.
//

import SwiftUI

struct ImportSuccessView: View {
    let kind: ImportFlowSuccessKind
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isVisible = false

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 54, weight: .semibold))
                .foregroundStyle(.green)
                .scaleEffect(reduceMotion || isVisible ? 1 : 0.85)

            Text("import.success.title")
                .font(.title2.weight(.semibold))

            Text(LocalizedStringKey(kind.messageKey))
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .multilineTextAlignment(.center)
        .padding(.horizontal, 28)
        .padding(.vertical, 24)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
        .shadow(radius: 12, y: 6)
        .padding()
        .onAppear {
            guard reduceMotion == false else {
                isVisible = true
                return
            }

            withAnimation(.spring(response: 0.28, dampingFraction: 0.82)) {
                isVisible = true
            }
        }
    }
}

#Preview {
    ImportSuccessView(kind: .profile)
}
