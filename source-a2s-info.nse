local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries a Source engine game server using A2S_INFO and A2S_PLAYER and displays
server details (name, map, game, player counts, OS, VAC, version, extra data)
along with the list of connected players (name, score, time connected).

Handles the challenge-response mechanism used by modern Source servers.

A2S responses documentation: https://developer.valvesoftware.com/wiki/Server_queries
]]

---
-- @usage
-- nmap -sU -p 27015 --script source-a2s-info <target>
-- nmap -sU -p 27015 --script source-a2s-info --script-args source-a2s-info.players=false <target>
--
-- @args source-a2s-info.players Set to false to skip the A2S_PLAYER query. Default: true
--
-- @output
-- PORT      STATE SERVICE
-- 27015/udp open  unknown
-- | source-a2s-info:
-- |   name: test server
-- |   map: de_dust2
-- |   game: Counter-Strike: Global Offensive
-- |   players: 2/32 (0 bots)
-- |   ...
-- |   player_list:
-- |     Alice (score: 14, time: 00:21:07)
-- |_    Bob (score: 3, time: 00:05:42)

author = "Kate Aubrey Cellan"
license = "GNU General Public License v3.0--See https://www.gnu.org/licenses/gpl-3.0.en.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "udp"
    and (port.state == "open" or port.state == "open|filtered")
end

local HEADER = "\xFF\xFF\xFF\xFF"
local A2S_INFO = HEADER .. "T" .. "Source Engine Query\0"
local A2S_PLAYER_PREFIX = HEADER .. "U"
local NO_CHALLENGE = "\xFF\xFF\xFF\xFF"
local TIMEOUT = 2000 -- Change timeout as needed

local SERVER_TYPES = { d = "Dedicated", l = "Listen", p = "SourceTV relay" }
local ENVIRONMENTS = { l = "Linux", w = "Windows", m = "Mac", o = "Mac" }

local function exchange(socket, payload)
  local ok, err = socket:send(payload)
  if not ok then return nil, err end
  return socket:receive()
end

-- Sends a request, and if the server answers with a challenge (0x41),
-- resends it with the challenge appended. `build` takes a challenge string
-- (or nil) and returns the packet to send.
local function query(socket, build, initial_challenge)
  local status, resp = exchange(socket, build(initial_challenge))
  if not status then return nil end

  if #resp >= 9 and resp:sub(1, 4) == HEADER and resp:byte(5) == 0x41 then
    local challenge = resp:sub(6, 9)
    status, resp = exchange(socket, build(challenge))
    if not status then return nil end
  end
  return resp
end

local function format_duration(seconds)
  seconds = math.max(0, math.floor(seconds))
  return ("%02d:%02d:%02d"):format(seconds // 3600, (seconds % 3600) // 60, seconds % 60)
end

local function parse_info(data)
  local ok, protocol, name, map, folder, game, app_id, players, max_players,
        bots, stype, env, visibility, vac, pos = pcall(string.unpack,
          "<B z z z z I2 B B B c1 c1 B B", data, 6)
  if not ok then return nil end

  local info = stdnse.output_table()
  info.protocol = protocol
  info.name = name
  info.map = map
  info.folder = folder
  info.game = game
  info.app_id = app_id
  info.players = ("%d/%d (%d bots)"):format(players, max_players, bots)
  info.server_type = SERVER_TYPES[stype] or stype
  info.environment = ENVIRONMENTS[env] or env
  info.visibility = visibility == 0 and "Public" or "Private"
  info.vac = vac == 1 and "Secure" or "Insecure"

  -- The Ship (app id 2400) has extra fields
  if app_id == 2400 then
    local ok2, mode, witnesses, duration, npos = pcall(string.unpack, "<B B B", data, pos)
    if ok2 then
      info.ship_mode = mode
      info.ship_witnesses = witnesses
      info.ship_duration = duration
      pos = npos
    end
  end

  local ok3, version, npos = pcall(string.unpack, "z", data, pos)
  if not ok3 then return info end
  info.version = version
  pos = npos

  -- Extra Data Flag
  if pos <= #data then
    local edf
    edf, pos = string.unpack("<B", data, pos)
    pcall(function()
      if edf & 0x80 ~= 0 then
        info.game_port, pos = string.unpack("<I2", data, pos)
      end
      if edf & 0x10 ~= 0 then
        local sid
        sid, pos = string.unpack("<I8", data, pos)
        info.steam_id = ("%d"):format(sid)
      end
      if edf & 0x40 ~= 0 then
        local sport, sname
        sport, sname, pos = string.unpack("<I2 z", data, pos)
        info.sourcetv_port = sport
        info.sourcetv_name = sname
      end
      if edf & 0x20 ~= 0 then
        info.keywords, pos = string.unpack("z", data, pos)
      end
      if edf & 0x01 ~= 0 then
        local gid
        gid, pos = string.unpack("<I8", data, pos)
        info.game_id = ("%d"):format(gid)
      end
    end)
  end

  return info
end

-- Response layout: header (4), 0x44, player count (1)
-- Per player: index (1), name (string), score (int32), duration (float32, seconds)
local function parse_players(data)
  local ok, count, pos = pcall(string.unpack, "<B", data, 6)
  if not ok then return nil end

  local players = {}
  for _ = 1, count do
    local ok2, _, name, score, duration, npos = pcall(string.unpack, "<B z i4 f", data, pos)
    if not ok2 then break end
    pos = npos
    if name == "" then name = "<connecting>" end
    players[#players + 1] = ("%s (score: %d, time: %s)"):format(
      name, score, format_duration(duration))
  end
  return players
end

action = function(host, port)
  local socket = nmap.new_socket("udp")
  socket:set_timeout(stdnse.get_timeout(host, TIMEOUT))

  local ok, err = socket:connect(host, port)
  if not ok then
    return stdnse.format_output(false, "Connect failed: " .. tostring(err))
  end

  -- A2S_INFO
  local resp = query(socket, function(challenge)
    return A2S_INFO .. (challenge or "")
  end)

  if not resp then
    socket:close()
    return nil
    -- no response, high likely not a Source server or server refuses to respond for some reason?
    -- who knows? its sorse
  end

  if #resp < 6 or resp:sub(1, 4) ~= HEADER or resp:byte(5) ~= 0x49 then
    socket:close()
    stdnse.debug1("Unexpected A2S_INFO response header from %s:%d", host.ip, port.number)
    return nil
  end

  local info = parse_info(resp)
  if not info then
    socket:close()
    return nil
  end

  port.version.name = "source-engine"
  port.version.product = info.game
  port.version.version = info.version
  nmap.set_port_version(host, port)

  -- A2S_PLAYER
  local want_players = stdnse.get_script_args("source-a2s-info.players")
  if want_players == nil or want_players == "true" or want_players == true or want_players == "1" then
    local presp = query(socket, function(challenge)
      return A2S_PLAYER_PREFIX .. (challenge or NO_CHALLENGE)
    end, nil)

    if presp and #presp >= 6 and presp:sub(1, 4) == HEADER and presp:byte(5) == 0x44 then
      local players = parse_players(presp)
      if players and #players > 0 then
        info.player_list = players
      elseif players then
        info.player_list = "none connected"
      end
    else
      stdnse.debug1("No valid A2S_PLAYER response from %s:%d", host.ip, port.number)
    end
  end

  socket:close()
  return info
end
