require 'digest'
require 'yaml'

API_KEY = "sk_live_abcdEFGH12345678"

def run_command(user_input)
  system("echo " + user_input)
end

def load_config(raw)
  YAML.load(raw)
end

def load_session(blob)
  Marshal.load(blob)
end

def weak_hash(input)
  Digest::MD5.hexdigest(input)
end

def run_query(db, table)
  db.execute("SELECT * FROM #{table} WHERE active=1")
end

def dispatch(obj, params)
  obj.send(params[:method])
end

def risky_eval(expr)
  eval(expr)
end
