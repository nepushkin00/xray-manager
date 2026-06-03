"use strict";

const assert = require("assert");
const {
  parseVlessLink,
  decodeSubscriptionText,
  extractLinks,
  generateXrayConfig,
  defaultState
} = require("../server");

const link = "vless://00000000-0000-4000-8000-000000000000@demo.example.invalid:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=demo.example.invalid&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0000000000000000&type=tcp#Demo";

const profile = parseVlessLink(link);
assert.equal(profile.protocol, "vless");
assert.equal(profile.address, "demo.example.invalid");
assert.equal(profile.port, 443);
assert.equal(profile.security, "reality");
assert.equal(profile.flow, "xtls-rprx-vision");
assert.equal(profile.name, "Demo");

const encoded = Buffer.from(`${link}\n`).toString("base64");
assert.equal(decodeSubscriptionText(encoded).trim(), link);
assert.deepEqual(extractLinks(encoded), [link]);

const state = defaultState();
state.profiles.push(profile);
state.activeProfileId = profile.id;
const config = generateXrayConfig(state);
assert.equal(config.inbounds[0].protocol, "socks");
assert.equal(config.outbounds[0].protocol, "vless");
assert.equal(config.outbounds[0].streamSettings.security, "reality");
assert.equal(config.routing.rules.at(-1).outboundTag, "proxy");

console.log("parser tests passed");
