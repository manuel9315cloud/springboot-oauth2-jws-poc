package com.poc.oauth.wam.security;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JtiReplayProtection {

    private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

    public boolean register(String jti) {
        return usedJtis.add(jti);
    }
}