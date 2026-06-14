// Copyright (c) 2026 DGKN@Labs. All rights reserved.
// SPDX-License-Identifier: LicenseRef-DGKN-Evaluation
// Part of the DGKN@Labs Crypto Suite v7.0.0 — see LICENSE (Evaluation License).

#include "Totp.hpp"
#include "../Config.hpp"

#include <sodium.h>
#include <array>
#include <vector>
#include <cstring>
#include <ctime>
#include <cctype>

namespace dgkn::core {

    namespace {
        // ── SHA-1 (RFC 3174) ── libsodium bietet kein SHA-1; TOTP verlangt es.
        // Eigene, gegen RFC-Vektoren testbare Implementierung.
        struct Sha1 {
            uint32_t h[5];
            uint64_t len_bits;
            uint8_t buf[64];
            size_t buf_len;

            void init() {
                h[0]=0x67452301; h[1]=0xEFCDAB89; h[2]=0x98BADCFE; h[3]=0x10325476; h[4]=0xC3D2E1F0;
                len_bits=0; buf_len=0;
            }
            static uint32_t rol(uint32_t v, int b){ return (v<<b)|(v>>(32-b)); }
            void block(const uint8_t* p) {
                uint32_t w[80];
                for (int i=0;i<16;++i)
                    w[i]=(uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|(uint32_t(p[i*4+2])<<8)|uint32_t(p[i*4+3]);
                for (int i=16;i<80;++i) w[i]=rol(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
                uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
                for (int i=0;i<80;++i){
                    uint32_t f,k;
                    if(i<20){ f=(b&c)|((~b)&d); k=0x5A827999; }
                    else if(i<40){ f=b^c^d; k=0x6ED9EBA1; }
                    else if(i<60){ f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC; }
                    else { f=b^c^d; k=0xCA62C1D6; }
                    uint32_t t=rol(a,5)+f+e+k+w[i];
                    e=d; d=c; c=rol(b,30); b=a; a=t;
                }
                h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e;
            }
            void update(const uint8_t* data, size_t n) {
                len_bits += uint64_t(n)*8;
                while (n) {
                    size_t take = 64-buf_len; if (take>n) take=n;
                    std::memcpy(buf+buf_len, data, take);
                    buf_len+=take; data+=take; n-=take;
                    if (buf_len==64){ block(buf); buf_len=0; }
                }
            }
            void final(uint8_t out[20]) {
                // Nachrichtenlänge VOR dem Padding sichern (update() würde len_bits
                // sonst durch die Padding-Bytes weiter hochzählen -> falscher Hash).
                uint64_t total_bits = len_bits;
                uint8_t lb[8];
                for (int i=0;i<8;++i) lb[i]=uint8_t((total_bits>>(56-i*8))&0xFF);

                uint8_t pad=0x80; update(&pad,1);
                uint8_t z=0; while (buf_len!=56) update(&z,1);
                // Längenfeld direkt in den Block schreiben (ohne len_bits zu verändern).
                std::memcpy(buf+56, lb, 8);
                block(buf);
                buf_len=0;

                for (int i=0;i<5;++i){ out[i*4]=uint8_t(h[i]>>24); out[i*4+1]=uint8_t(h[i]>>16); out[i*4+2]=uint8_t(h[i]>>8); out[i*4+3]=uint8_t(h[i]); }
            }
        };

        void sha1(const uint8_t* data, size_t n, uint8_t out[20]) {
            Sha1 s; s.init(); s.update(data,n); s.final(out);
        }

        // HMAC-SHA1 (RFC 2104), Blockgröße 64.
        void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[20]) {
            uint8_t k[64]; std::memset(k,0,64);
            if (key_len>64) { sha1(key,key_len,k); } else { std::memcpy(k,key,key_len); }
            uint8_t ipad[64], opad[64];
            for (int i=0;i<64;++i){ ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5C; }
            uint8_t inner[20];
            { Sha1 s; s.init(); s.update(ipad,64); s.update(msg,msg_len); s.final(inner); }
            { Sha1 s; s.init(); s.update(opad,64); s.update(inner,20); s.final(out); }
            sodium_memzero(k,sizeof k); sodium_memzero(ipad,sizeof ipad); sodium_memzero(opad,sizeof opad);
        }

        // Base32-Decode (RFC 4648), tolerant: Groß-/Kleinschreibung, Whitespace, optionales Padding.
        bool base32_decode(const std::string& in, std::vector<uint8_t>& out) {
            auto val=[](char c)->int{
                if (c>='A'&&c<='Z') return c-'A';
                if (c>='a'&&c<='z') return c-'a';
                if (c>='2'&&c<='7') return c-'2'+26;
                return -1;
            };
            uint32_t buffer=0; int bits=0; out.clear();
            for (char c : in) {
                if (c=='='||c==' '||c=='\t'||c=='\r'||c=='\n') continue;
                int v=val(c);
                if (v<0) return false; // ungültiges Zeichen
                buffer=(buffer<<5)|uint32_t(v); bits+=5;
                if (bits>=8){ bits-=8; out.push_back(uint8_t((buffer>>bits)&0xFF)); }
            }
            return !out.empty();
        }

        std::string url_encode(const std::string& s) {
            static const char* hex="0123456789ABCDEF";
            std::string o;
            for (unsigned char c : s) {
                if (std::isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') o+=char(c);
                else { o+='%'; o+=hex[c>>4]; o+=hex[c&0xF]; }
            }
            return o;
        }
    }

    std::string Totp::generate_secret() {
        // 20 Zufallsbytes -> Base32, ohne Padding (wie Authenticator-Apps erwarten).
        uint8_t raw[20]; randombytes_buf(raw, sizeof raw);
        static const char* B32="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string out; uint32_t buffer=0; int bits=0;
        for (uint8_t b : raw) {
            buffer=(buffer<<8)|b; bits+=8;
            while (bits>=5){ bits-=5; out+=B32[(buffer>>bits)&0x1F]; }
        }
        if (bits>0) out+=B32[(buffer<<(5-bits))&0x1F];
        sodium_memzero(raw,sizeof raw);
        return out;
    }

    bool Totp::is_valid_secret(const std::string& base32_secret) {
        // F-E: billige Längenprüfung zuerst, dann erst dekodieren.
        if (base32_secret.size() < 8) return false;
        std::vector<uint8_t> key;
        bool ok = base32_decode(base32_secret, key);
        sodium_memzero(key.data(), key.size());
        return ok;
    }

    std::optional<std::string> Totp::code(const std::string& base32_secret, int64_t unix_time) {
        std::vector<uint8_t> key;
        if (!base32_decode(base32_secret, key)) return std::nullopt;

        int64_t t = (unix_time < 0) ? static_cast<int64_t>(std::time(nullptr)) : unix_time;
        uint64_t counter = static_cast<uint64_t>(t) / config::TWOFA_PERIOD;

        uint8_t msg[8];
        for (int i=0;i<8;++i) msg[i]=uint8_t((counter>>(56-i*8))&0xFF);

        uint8_t dig[20];
        hmac_sha1(key.data(), key.size(), msg, 8, dig);
        sodium_memzero(key.data(), key.size());

        int off = dig[19] & 0x0F;
        uint32_t dbc = ((uint32_t(dig[off])&0x7F)<<24) | (uint32_t(dig[off+1])<<16)
                     | (uint32_t(dig[off+2])<<8) | uint32_t(dig[off+3]);
        uint32_t mod = 1; for (size_t i=0;i<config::TWOFA_DIGITS;++i) mod*=10;
        uint32_t val = dbc % mod;

        std::string s = std::to_string(val);
        while (s.size() < config::TWOFA_DIGITS) s.insert(s.begin(), '0');
        sodium_memzero(dig, sizeof dig);
        return s;
    }

    bool Totp::verify(const std::string& base32_secret, const std::string& user_code, int64_t unix_time) {
        // Nur Ziffern extrahieren.
        std::string clean;
        for (char c : user_code) if (c>='0'&&c<='9') clean+=c;
        if (clean.size() != config::TWOFA_DIGITS) return false;
        if (base32_secret.empty()) return false;

        int64_t now = (unix_time < 0) ? static_cast<int64_t>(std::time(nullptr)) : unix_time;
        int w = static_cast<int>(config::TWOFA_WINDOW);
        bool match = false;
        // Alle Fenster prüfen OHNE Early-Exit (konstante Anzahl Iterationen gegen Timing-Leak).
        for (int i=-w;i<=w;++i) {
            auto c = code(base32_secret, now + int64_t(i)*int64_t(config::TWOFA_PERIOD));
            if (c && c->size()==clean.size() &&
                sodium_memcmp(c->data(), clean.data(), clean.size())==0) {
                match = true;
            }
        }
        return match;
    }

    std::string Totp::otpauth_uri(const std::string& base32_secret,
                                  const std::string& issuer, const std::string& account) {
        std::string label = issuer + ":" + account;
        return "otpauth://totp/" + url_encode(label)
             + "?secret=" + base32_secret
             + "&issuer=" + url_encode(issuer)
             + "&algorithm=SHA1&digits=" + std::to_string(config::TWOFA_DIGITS)
             + "&period=" + std::to_string(config::TWOFA_PERIOD);
    }

}