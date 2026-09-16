import Foundation

let apiKey: String = "sk_live_abcdEFGH12345678"

func runCommand(_ userInput: String) {
    let task = Process()
    task.arguments = ["-c", "echo \(userInput)"]
}

func weakHash(_ input: String) -> String {
    return CC_MD5(input)
}

func buildQuery(_ table: String) -> String {
    return "SELECT * FROM \(table) WHERE active=1"
}

func saveToken(_ token: String) {
    UserDefaults.standard.set(token, forKey: "authToken")
}

func readInput() -> Int {
    return Int(readLine()!)!
}
