package com.phishguard.blockchain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishguard.util.UrlSanitizer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Local Proof-of-Work, tamper-evident hash-chain ledger for threat intelligence recording.
 * Provides thread-safe transaction mining and cryptographic verification across concurrent requests.
 * Sensitive URL query parameters, tokens, and PII are redacted prior to block incorporation.
 */
@Component
@Slf4j
public class PhishChain {

    @Value("${blockchain.difficulty:3}")
    private int difficulty;

    @Value("${blockchain.node-id:node-1}")
    private String nodeId;

    private final List<Block> chain = new CopyOnWriteArrayList<>();
    private final List<PendingTransaction> mempool = new CopyOnWriteArrayList<>();
    private final ObjectMapper mapper = new ObjectMapper();

    // ── Block ────────────────────────────────────

    public static class Block {
        public long index;
        public long timestamp;
        public String previousHash;
        public String hash;
        public long nonce;
        public String merkleRoot;
        public String nodeId;
        public List<Map<String, Object>> transactions;

        public Block(long index, String previousHash, List<Map<String,Object>> txns, String nodeId) {
            this.index        = index;
            this.timestamp    = Instant.now().toEpochMilli();
            this.previousHash = previousHash;
            this.transactions = txns;
            this.nonce        = 0;
            this.nodeId       = nodeId;
            this.merkleRoot   = buildMerkleRoot(txns);
            this.hash         = "";
        }
    }

    public static class PendingTransaction {
        public String txId;
        public Map<String, Object> data;
        public long createdAt;
        public PendingTransaction(Map<String,Object> data) {
            this.txId      = UUID.randomUUID().toString().substring(0, 8);
            this.data      = data;
            this.createdAt = Instant.now().toEpochMilli();
        }
    }

    // ── Init ─────────────────────────────────────

    public PhishChain() {
        chain.add(genesisBlock());
        log.info("[PhishChain] Initialized thread-safe hash-chain ledger with genesis block");
    }

    // ── Public API (Synchronized for Concurrency Safety) ───────────────────────

    /** Add single threat — immediately mines a block */
    public synchronized String addThreat(Map<String, Object> threatData) {
        Map<String, Object> sanitizedData = new LinkedHashMap<>(threatData);
        if (sanitizedData.containsKey("url")) {
            sanitizedData.put("url", UrlSanitizer.sanitizeUrl((String) sanitizedData.get("url")));
        }
        sanitizedData.put("tx_id", UUID.randomUUID().toString().substring(0, 8));
        sanitizedData.put("tx_time", Instant.now().toString());

        Block b = mineBlock(List.of(sanitizedData));
        chain.add(b);
        log.info("[PhishChain] Block #{} mined hash={}", b.index, b.hash.substring(0, Math.min(12, b.hash.length())) + "...");
        return b.hash;
    }

    /** Queue threat to mempool, mine when >= 3 pending */
    public synchronized String queueThreat(Map<String, Object> threatData) {
        Map<String, Object> sanitizedData = new LinkedHashMap<>(threatData);
        if (sanitizedData.containsKey("url")) {
            sanitizedData.put("url", UrlSanitizer.sanitizeUrl((String) sanitizedData.get("url")));
        }
        mempool.add(new PendingTransaction(sanitizedData));
        if (mempool.size() >= 3) return flushMempool();
        return "PENDING";
    }

    public synchronized String flushMempool() {
        if (mempool.isEmpty()) return null;
        List<Map<String,Object>> txns = mempool.stream().map(t -> t.data).toList();
        mempool.clear();
        Block b = mineBlock(txns);
        chain.add(b);
        return b.hash;
    }

    public synchronized boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block cur  = chain.get(i);
            Block prev = chain.get(i - 1);
            if (!cur.hash.equals(computeHash(cur)))        return false;
            if (!cur.previousHash.equals(prev.hash))       return false;
            if (!cur.merkleRoot.equals(buildMerkleRoot(cur.transactions))) return false;
        }
        return true;
    }

    public synchronized List<Block>  getChain()       { return List.copyOf(chain); }
    public synchronized Block        getLatestBlock() { return chain.get(chain.size() - 1); }
    public synchronized int          getChainLength() { return chain.size(); }
    public synchronized int          getMempoolSize() { return mempool.size(); }
    public synchronized List<PendingTransaction> getMempool() { return List.copyOf(mempool); }

    // ── Mining ───────────────────────────────────

    private Block mineBlock(List<Map<String,Object>> txns) {
        Block prev = chain.get(chain.size() - 1);
        Block b    = new Block(chain.size(), prev.hash, txns, nodeId);
        String target = "0".repeat(Math.max(1, Math.min(4, difficulty)));
        long start = System.currentTimeMillis();
        while (!b.hash.startsWith(target)) {
            b.nonce++;
            b.hash = computeHash(b);
        }
        long elapsed = System.currentTimeMillis() - start;
        log.debug("[PhishChain] Mined in {}ms nonce={}", elapsed, b.nonce);
        return b;
    }

    // ── Hashing ──────────────────────────────────

    private String computeHash(Block b) {
        String raw = b.index + b.timestamp + b.previousHash
                   + b.nonce + b.merkleRoot + b.nodeId;
        return sha256(raw);
    }

    private static String buildMerkleRoot(List<Map<String,Object>> txns) {
        if (txns == null || txns.isEmpty()) return sha256("empty");
        List<String> hashes = txns.stream().map(t -> sha256(t.toString())).toList();
        List<String> level  = new ArrayList<>(hashes);
        while (level.size() > 1) {
            List<String> next = new ArrayList<>();
            for (int i = 0; i < level.size(); i += 2) {
                String left  = level.get(i);
                String right = (i + 1 < level.size()) ? level.get(i + 1) : left;
                next.add(sha256(left + right));
            }
            level = next;
        }
        return level.get(0);
    }

    public static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private Block genesisBlock() {
        Block g = new Block(0, "0000000000000000",
            List.of(Map.of("type","GENESIS","msg","PhishSense Proof-of-Work Threat Ledger v4.0")), "genesis");
        g.hash = sha256("PHISHSENSE_GENESIS_V4");
        return g;
    }
}
