"""Intentionally vulnerable fixture: Flask misconfiguration triggers."""

class FakeFlaskApp:
    def run(self, host=None, debug=None):
        print(f"pretend server running host={host} debug={debug}")


app = FakeFlaskApp()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # PY-DEBUG-FLASK + PY-BIND-ALL
