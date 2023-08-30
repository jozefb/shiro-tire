package com.bit.authz.shiro

fun newTrie(): ShiroTrie {
    return ShiroTrieImpl(emptyList())
}

fun newTrie(permissions: List<String>?): ShiroTrie {
    return ShiroTrieImpl(permissions ?: emptyList())
}

interface ShiroTrie {
    fun reset(): ShiroTrie
    fun add(permission: String): ShiroTrie
    fun add(permissions: List<String>): ShiroTrie
    fun check(permission: String): Boolean

    fun permissions(search: String): List<String>
}

private class ShiroTrieImpl(permissions: List<String>) : ShiroTrie {

    private var data: MutableMap<String, Any> = HashMap()

    init {
        this.add(permissions)
    }

    private fun _add(trie: MutableMap<String, Any>, permission: List<String>): MutableMap<String, Any> {
        var goRecursive = false
        var subPerms: List<String>? = null
        var node = trie
        // go through permission string array
        var breakOuterLoop = false
        for (i in permission.indices) {
            if (breakOuterLoop) break
            // split by comma
            val values = permission[i].split(',')
            // default: only once (no comma separation)
            for (j in values.indices) {
                // permission is new -> create
                val value = values[j]
                var valueMap: HashMap<String, Any>? = node[value] as? HashMap<String, Any>
                if (valueMap == null) {
                    valueMap = HashMap()
                    node[value] = valueMap
                } else if (node.containsKey("*")) {
                    val any: HashMap<String, Any> = node["*"] as HashMap<String, Any>
                    if (any.isEmpty()) {
                        return trie
                    }
                }

                if (values.size > 1) {
                    // if we have a comma separated permission list, we have to go recursive
                    // save the remaining permission array (subTrie has to be appended to each one)
                    if (!goRecursive) {
                        subPerms = if (permission.size > (i + 1)) permission.slice((i + 1) until permission.size) else null
                        goRecursive = true
                    }
                    // call recursion for this subTrie
                    node[value] = _add(trie = valueMap, permission = subPerms ?: emptyList())
                    // break outer loop
                    breakOuterLoop = true
                } else {
                    // if we don't need recursion, we just go deeper
                    node = valueMap
                }
            }
        }

        // if we did not went recursive, we close the Trie with a * leaf
        if (!goRecursive) {
            node["*"] = emptyMap<String, Any>()
        }

        return trie
    }

    override fun add(permission: String): ShiroTrie {
        return add(listOf(permission))
    }
    override fun add(permissions: List<String>): ShiroTrie {
        for (permission in permissions) {
            var array = permission.split(":")
            if (array[array.size - 1] == "*") {
                array = array.dropLast(1)
            }

            this.data = this._add(trie = this.data, permission = array)
        }

        return this
    }

    override fun reset(): ShiroTrie {
        this.data = HashMap()
        return this
    }

    fun uniq(permissions: List<String>): List<String> {
        return HashSet(permissions).toList()
    }

    fun _expand(permission: String): List<String> {
        var results: List<String> = ArrayList<String>()
        val parts = permission.split(':')
        for (part in parts) {
            var alternatives: List<String> = part.split(',')
            if (results.isEmpty()) {
                results = alternatives
            } else {
                alternatives = alternatives.flatMap { alternative -> results.map { perm -> "$perm:$alternative" } }
                results = uniq(alternatives)
            }
        }

        return results
    }

    private fun hasEmptyAny(node: Map<String, Any>): Boolean {
        val any: Map<String, Any>? = node["*"] as? Map<String, Any>
        if (any != null && any.isEmpty()) {
            return true
        }

        return false
    }

    fun _check(trie: Map<String, Any>, permission: MutableList<String>): Boolean {
        // add implicit star at the end
        if (permission.isEmpty() || permission[permission.size - 1] !== "*") {
            permission.add("*")
        }

        var node = trie
        for (i in permission.indices) {
            val any: Map<String, Any>? = node["*"] as? Map<String, Any>
            if (hasEmptyAny(node)) {
                // if we find a star leaf in the trie, we are done (everything below is allowed)
                return true
            } else if (any != null && (permission[i] != "*" && node[permission[i]] != null)) {
                // if there are multiple paths, we have to go recursive
                val subPerm = permission.slice((i + 1) until permission.size).toMutableList()
                return _check(any, subPerm) || _check(node[permission[i]] as Map<String, Any>, subPerm)
            } else if (any != null) {
                // otherwise we have to go deeper
                node = any
            } else if (node[permission[i]] != null) {
                // otherwise we go deeper
                node = node[permission[i]] as Map<String, Any>
            } else {
                // if the wanted permission is not found, we return false
                if (node[permission[i]] == null) {
                    return false
                }
            }
        }

        return true
    }

    override fun check(permission: String): Boolean {
        if (permission.indexOf(',') != -1) { // expand string to single comma-less permissions...
            return _expand(permission).map { ep ->
                return _check(this.data, ep.split(':').toMutableList())
            }.all { it } // ... and make sure they are all allowed
        }

        return _check(this.data, permission.split(':').toMutableList())
    }

    fun _expandTrie(trie: Map<String, Any>?, array: List<String>): List<String> {
        if (trie.isNullOrEmpty()) {
            return emptyList()
        }

        return trie.keys.map { node ->
            var recurse = false
            if (node == "*") {
                if (array.size <= 1 || hasEmptyAny(trie)) {
                    return listOf(node)
                }
                recurse = true
            }
            if (node == "*" || array[0] == node || array[0] == "$") {
                if (array.size <= 1) {
                    return listOf(node)
                }
                recurse = true
            }

                if (!recurse) {
                return emptyList()
            }

            val child =
                _expandTrie(trie[node] as Map<String, Any>?, array.slice(1 until array.size))
            return child.map { inner -> "$node:$inner" }
        }
    }

    fun _permissions(trie: Map<String, Any>?, permission: List<String>): List<String> {
        if (trie.isNullOrEmpty() || permission.isEmpty()) {
            // for recursion safety, we make sure we have really valid values
            return emptyList()
        }

        // if we have a star permission with nothing further down the trie we can just return that
        if (hasEmptyAny(trie)) {
            return listOf("*")
        }

        // take first element from array
        val results: MutableList<String>
        val array = permission.toMutableList()
        val current: String = array.removeFirst()
        if (current == "?") {
            results = trie.keys.toMutableList()
            // if something is coming after the ?,
            if (array.isNotEmpty()) {
                val anyObj = HashMap<String, List<String>>()
                results.forEach { node ->
                    anyObj[node] = _expandTrie(trie[node] as Map<String, Any>?, array)
                }

                return results.filter { node -> !anyObj[node].isNullOrEmpty() }
            }
            return results
        }

        // if we have an 'any' flag, we have to go recursive for all alternatives
        if (current == "$") { // $ before ?
            results = ArrayList()
            trie.keys.forEach { node->
                results.addAll(_permissions(trie[node] as Map<String, Any>?, array))
            }

            // remove duplicates
            var u: List<String> = uniq(results)
            // … and * from results
            for (i in u.size - 1 downTo 0) {
                if (u[i] == "*") {
                    u = u.subList(0, if (i == 0) 0 else i-1)
                }
            }

            return u
        }
        results = ArrayList()
        if (trie[current] != null) {
            // we have to go deeper!
            results.addAll(_permissions(trie[current] as Map<String, Any>?, array))
        }
        if (trie["*"] != null) {
            // if we have a star permission we need to go deeper
            results.addAll(_permissions(trie["*"] as Map<String, Any>?, array))
        }
        return results
    }

    override fun permissions(search: String): List<String> {
        return this._permissions(this.data, search.split(':'))
    }
}
