package com.bit.authz.shiro

import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*

class ShiroTrieImplTest {

    @Test
    fun testNewTrie() {
        val trie = newTrie()
        assertFalse(trie.check(""))
    }

    @Test
    fun add() {
        val trie = newTrie()
        val result = trie.add("printer:xpc5000:print")
        assertSame(trie, result)
    }

    @Test
    fun reset() {
        val trie = newTrie(listOf(
            "printer:xpc5000:print",
            "printer:xpc4000:*",
            "scanner:xsc6000:scan"
        ))

        val result = trie.reset()
        assertSame(trie, result)
    }

    @Test
    fun check() {
        val trie = newTrie()
        trie.add(listOf(
            "printer:xpc5000:print",
            "printer:xpc4000:*",
            "scanner:xsc6000:scan"
        ))

        assertTrue(trie.check("printer:xpc4000:configure"))
        assertTrue(trie.check("printer:xpc4000:*"))
        assertFalse(trie.check("printer:xpc5000:scan"))
        assertTrue(trie.check("printer:xpc5000:print"))
        assertFalse(trie.check("scanner:xsc6000:print"))
    }

    @Test
    fun permissions() {
        val trie = newTrie()
        trie.add(listOf(
            "printer:xpc5000:print",
            "printer:xpc4000:*",
            "nas:timeCapsule,fritzbox:read"
        ))

        assertEquals(trie.permissions("printer:?"), listOf("xpc5000", "xpc4000"))
        assertEquals(trie.permissions("nas:$:?"), listOf("read"))
        assertEquals(trie.permissions("nas:?:read"), listOf("timeCapsule","fritzbox"))
        assertEquals(trie.permissions("nas:?:$"), listOf("timeCapsule","fritzbox"))
        assertEquals(trie.permissions("nas:?:print"), listOf<String>())
    }
}