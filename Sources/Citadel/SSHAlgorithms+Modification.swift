extension SSHAlgorithms {
    public enum Modification<T> {
        case replace(with: [T]), add([T])

        func apply(to configuration: inout [T]) {
            switch self {
            case .add(let algorithms): configuration.append(contentsOf: algorithms)
            case .replace(let algorithms): configuration = algorithms
            }
        }
    }
}

extension SSHAlgorithms.Modification: Sendable where T: Sendable {}
