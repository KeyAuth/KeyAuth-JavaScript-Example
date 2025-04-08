import { Buffer } from "buffer"
import { createInterface } from "readline"
import { execSync, exec } from "child_process"
import { verifyKey } from "discord-interactions"

import os from "os"
import fs from "fs"
import crypto from "crypto"
import * as QRCode from "qrcode"

const readline = createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
})

export default class KeyAuth {
  url = "https://keyauth.win/api/1.3/"
  public_key =
    "5586b4bc69c7a4b487e4563a4cd96afd39140f919bd31cea7d1c6a1e8439422b"
  loggingEnabled = true

  initialized = false

  user_data = null
  app_data = null

  constructor(options) {
    this.name = options.name
    this.ownerid = options.ownerid
    this.version = options.version
    this.hash_to_check = options.hash_to_check
    this.url = options.url ?? "https://keyauth.win/api/1.3/"
    this.path = options.path

    if (!this.name || !this.ownerid || !this.version) {
      throw new Error("Name, ownerid, and version are required")
    }
  }

  async init() {
    if (this.sessionid && this.initialized) {
      console.log("Application already initialized")
      return
    }

    let token = ""

    if (this.path) {
      try {
        token = fs.readFileSync(this.path, "utf-8").trim()
      } catch (error) {
        console.error(`Failed to read file at path ${this.path}:`, error)
        this.sleep(5000)
        process.exit(0)
      }
    }

    const post_data = {
      type: "init",
      name: this.name,
      ownerid: this.ownerid,
      version: this.version,
      hash: this.hash_to_check,
      ...(this.path && {
        token: token,
        thash: crypto
          .createHash("sha256")
          .update(token)
          .digest("hex")
      })
    }

    const response = await this.__do_request(post_data)

    if (response === "KeyAuth_Invalid") {
      console.log("This application does not exist")
      this.sleep(5000)
      process.exit(0)
    }

    if (response["message"] === "invalidver") {
      if (response["download"]) {
        console.log("Your application is outdated.")
        exec(`start ${response["download"]}`, error => {
          if (error) {
            console.error("Failed to open the download link:", error)
          }
        })
        this.sleep(5000)
        process.exit(0)
      } else {
        console.log(
          "Your application is outdated and no download link was provided, contact the owner for the latest app version."
        )
        this.sleep(5000)
        process.exit(0)
      }
    }

    if (response["success"] === false) {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }

    this.sessionid = response["sessionid"]
    this.initialized = true
  }

  async register(username, password, license, hwid) {
    this.checkinit()
    if (!hwid) hwid = this.get_hwid()

    const post_data = {
      type: "register",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      username: username,
      pass: password,
      key: license,
      hwid: hwid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      console.log(response["message"])
      this.__load_user_data(response["info"])
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async upgrade(username, license) {
    this.checkinit()

    const post_data = {
      type: "upgrade",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      username: username,
      key: license
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      console.log(response["message"])
      console.log("Restart the application to apply the changes.")
      this.sleep(5000)
      process.exit(0)
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async login(username, password, code, hwid) {
    this.checkinit()
    if (!hwid) hwid = this.get_hwid()

    const post_data = {
      type: "register",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      username: username,
      pass: password,
      hwid: hwid,

      ...(code && { code: code })
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      console.log(response["message"])
      this.__load_user_data(response["info"])
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async license(license, code, hwid) {
    this.checkinit()
    if (!hwid) hwid = this.get_hwid()

    const post_data = {
      type: "license",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      key: license,
      hwid: hwid,

      ...(code && { code: code })
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      console.log(response["message"])
      this.__load_user_data(response["info"])
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async var(name) {
    this.checkinit()

    const post_data = {
      type: "var",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      varid: name
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return response["message"]
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async getvar(name) {
    this.checkinit()

    const post_data = {
      type: "getvar",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      var: name
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return response["message"]
    } else {
      console.log(
        'NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse KeyAuthApp.var("{var_name}") for normal variables'
      )
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async setvar(name, value) {
    this.checkinit()

    const post_data = {
      type: "setvar",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      varid: name,
      data: value
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return true
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async ban() {
    this.checkinit()

    const post_data = {
      type: "ban",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return true
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async file(id) {
    this.checkinit()

    const post_data = {
      type: "file",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      fileid: id
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return Buffer.from(response["contents"], "hex")
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async webhook(id, param, body, conttype) {
    this.checkinit()

    const post_data = {
      type: "webhook",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      webid: id,
      params: param,
      body: body,
      conttype: conttype
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return response["message"]
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async check() {
    this.checkinit()

    const post_data = {
      type: "check",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return true
    } else {
      return false
    }
  }

  async checkblacklist() {
    this.checkinit()
    const hwid = this.get_hwid()

    const post_data = {
      type: "checkblacklist",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      hwid: hwid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return true
    } else {
      return false
    }
  }

  async log(message) {
    this.checkinit()

    const post_data = {
      type: "log",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      message: message,
      pcuser: os.userInfo().username
    }

    await this.__do_request(post_data)
  }

  async fetchOnline() {
    this.checkinit()

    const post_data = {
      type: "fetchOnline",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      if (Number(response["users"]) === 0) {
        return null
      } else {
        return Number(response["users"])
      }
    } else {
      return false
    }
  }

  async fetchStats() {
    this.checkinit()

    const post_data = {
      type: "fetchStats",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      this.__load_app_data(response["appinfo"])
    }
  }

  async chatGet(channel) {
    this.checkinit()

    const post_data = {
      type: "chatget",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      channel: channel
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return response["messages"]
    } else {
      return false
    }
  }

  async chatSend(message, channel) {
    this.checkinit()

    const post_data = {
      type: "chatsend",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      channel: channel,
      message: message
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      return true
    } else {
      return false
    }
  }

  async changeUsername(username) {
    this.checkinit()

    const post_data = {
      type: "changeUsername",
      newUsername: username,
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      console.log("Username changed successfully")
    } else {
      return false
    }
  }

  async logout() {
    this.checkinit()

    const post_data = {
      type: "logout",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      console.log("Logged out successfully")
      this.sleep(5000)
      process.exit(0)
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async enable2fa(code) {
    this.checkinit()

    const post_data = {
      type: "2faenable",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      ...(code && { code: code })
    }

    const response = await this.__do_request(post_data)

    if (response["success"] === true) {
      if (!code) {
        console.log(response)
        console.log(
          "Your 2fa secret code is: " + response["2fa"]["secret_code"]
        )

        this.displayQrCode(response["2fa"]["QRCode"])
        console.log(
          "Please enter the code you received in your authenticator app."
        )

        const userCode = await new Promise(resolve => {
          readline.question("Enter the code: ", input => {
            resolve(input)
          })
        })

        await this.enable2fa(userCode) // Recursively call with the entered code
      } else {
        console.log("2FA enabled successfully")
      }
    } else {
      console.log(response["message"])
      this.sleep(5000)
      process.exit(0)
    }
  }

  async disable2fa() {
    this.checkinit()

    const code = await new Promise(resolve => {
      readline.question("Enter the code: ", input => {
        resolve(input)
      })
    })

    const post_data = {
      type: "2fadisable",
      name: this.name,
      ownerid: this.ownerid,
      sessionid: this.sessionid,
      code: code
    }

    const response = await this.__do_request(post_data)

    console.log(response["message"])
    await this.sleep(5000)
  }

  async checkinit() {
    if (!this.sessionid && !this.initialized) {
      console.log("Application not initialized")
      this.sleep(5000)
      process.exit(0)
    }
  }

  get_hwid() {
    const platform = os.platform()

    if (platform === "linux") {
      try {
        const hwid = fs.readFileSync("/etc/machine-id", "utf-8").trim()
        return hwid
      } catch (error) {
        console.error("Error reading /etc/machine-id:", error)
        throw new Error("Failed to retrieve HWID on Linux")
      }
    } else if (platform === "win32") {
      try {
        const winUser = os.userInfo().username
        const sidOutput = execSync(
          `wmic useraccount where name='${winUser}' get sid`
        )
          .toString()
          .split("\n")
        const sid = sidOutput[1]?.trim()
        if (!sid) {
          throw new Error("Failed to retrieve SID on Windows: SID is undefined")
        }
        return sid
      } catch (error) {
        console.error("Error retrieving SID on Windows:", error)
        throw new Error("Failed to retrieve HWID on Windows")
      }
    } else if (platform === "darwin") {
      try {
        const output = execSync(
          "ioreg -l | grep IOPlatformSerialNumber"
        ).toString()
        const parts = output.split("=")
        const serial = parts[1]?.trim().replace(/"/g, "") ?? ""
        return serial
      } catch (error) {
        console.error("Error retrieving serial number on macOS:", error)
        throw new Error("Failed to retrieve HWID on macOS")
      }
    } else {
      throw new Error("Unsupported platform for HWID retrieval")
    }
  }

  async displayQrCode(qrCodeUrl) {
    try {
      const qrCode = await QRCode.toDataURL(qrCodeUrl)

      const base64Data = qrCode.split(",")[1]
      if (!base64Data) {
        throw new Error("Invalid QR code data")
      }
      const img = Buffer.from(base64Data, "base64")

      const outputPath = this.path ?? "qrcode.png"
      fs.writeFileSync(outputPath, img)

      const platform = os.platform()
      let openCommand

      if (platform === "win32") {
        openCommand = `start ${outputPath}`
      } else if (platform === "darwin") {
        openCommand = `open ${outputPath}`
      } else if (platform === "linux") {
        openCommand = `xdg-open ${outputPath}`
      } else {
        console.error("Unsupported platform for opening the QR code image")
        return
      }

      exec(openCommand, error => {
        if (error) {
          console.error("Failed to display the QR code image:", error)
        }
      })
    } catch (error) {
      console.error("Failed to generate QR code:", error)
    }
  }

  getCheckSum() {
    const md5Hash = crypto.createHash("md5")
    const file = fs.readFileSync(process.argv.slice(2).join(""), {
      encoding: "binary"
    })
    md5Hash.update(file)
    const digest = md5Hash.digest("hex")
    return digest
  }

  // Private functions (cannot be called from outside the class)
  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  async __do_request(data) {
    try {
      const response = await fetch(this.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        // @ts-ignore - Why does it error? No fucking clue but it works
        body: new URLSearchParams(data).toString()
      })

      if (!response.ok) {
        console.error(`HTTP error! Status: ${response.status}`)
        this.sleep(5000)
        process.exit(0)
      }

      const responseData = await response.json()
      const dontRunExtra = ["log", "file", "2faenable", "2fadisable"]
      if (dontRunExtra.includes(data.type)) {
        return responseData
      }

      const signature = response.headers.get("x-signature-ed25519")
      const timestamp = response.headers.get("x-signature-timestamp")
      if (!signature || !timestamp) {
        console.log("Missing signature or timestamp in response headers")
        this.sleep(5000)
        process.exit(0)
      }

      const server_time = new Date(Number(timestamp) * 1000).toUTCString()
      const current_time = new Date().toUTCString()

      const buffer_seconds = 5 // Allowable time difference in seconds
      const time_difference =
        Math.abs(
          new Date(server_time).getTime() - new Date(current_time).getTime()
        ) / 1000

      if (time_difference > buffer_seconds + 20) {
        console.log(
          `Time difference is too large: ${time_difference} seconds, try syncing your date and time settings.`
        )
        this.sleep(5000)
        process.exit(0)
      }

      if (
        !verifyKey(
          Buffer.from(JSON.stringify(responseData), "utf-8"),
          signature,
          timestamp,
          this.public_key
        )
      ) {
        console.log(
          "Signature checksum failed. Request was tampered with or session ended most likely."
        )
        await this.sleep(3000)
        process.exit(0)
      }

      this.logEvent(JSON.stringify(responseData) + "\n")

      return responseData
    } catch (error) {
      console.error("Unexpected error:", error)
      this.sleep(5000)
      process.exit(0)
    }
  }

  logEvent(message) {
    console.log(message)
    if (!this.loggingEnabled) return

    const exeName =
      process.argv[1].split("\\").pop() || process.argv[1].split("/").pop()
    const logDirectory = `${os.homedir()}/AppData/Roaming/KeyAuth/debug/${exeName}`

    try {
      if (!fs.existsSync(logDirectory)) {
        fs.mkdirSync(logDirectory, { recursive: true })
      }

      const logFileName = `${new Date()
        .toLocaleDateString("en-US", {
          month: "short",
          day: "2-digit",
          year: "numeric"
        })
        .replace(/ /g, "_")}_logs.txt`
      const logFilePath = `${logDirectory}/${logFileName}`

      // Redact sensitive fields
      message = this.redactField(message, "sessionid")
      message = this.redactField(message, "ownerid")
      message = this.redactField(message, "app")
      message = this.redactField(message, "version")
      message = this.redactField(message, "fileid")
      message = this.redactField(message, "webhooks")
      message = this.redactField(message, "nonce")

      const logMessage = `[${new Date().toISOString()}] [${exeName}] ${message}\n`
      fs.appendFileSync(logFilePath, logMessage, "utf-8")
    } catch (error) {
      if (error instanceof Error) {
        console.error(`Error logging data: ${error.message}`)
      } else {
        console.error("Error logging data: Unknown error")
      }
    }
  }

  redactField(content, field) {
    const regex = new RegExp(`"${field}":\\s*".*?"`, "g")
    return content.replace(regex, `"${field}": "[REDACTED]"`)
  }

  __load_app_data(data) {
    this.app_data = {
      numUsers: data["numUsers"],
      numKeys: data["numKeys"],
      app_ver: data["version"],
      customer_panel: data["customerPanelLink"],
      onlineUsers: data["numOnlineUsers"]
    }
  }

  __load_user_data(data) {
    this.user_data = {
      username: data["username"],
      ip: data["ip"],
      hwid: data["hwid"] || "N/A",
      expires: data["subscriptions"][0]["expiry"],
      createdate: data["createdate"],
      lastlogin: data["lastlogin"],
      subscription: data["subscriptions"][0]["subscription"],
      subscriptions: data["subscriptions"]
    }
  }
}
