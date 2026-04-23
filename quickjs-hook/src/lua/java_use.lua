-- Java.use() — Frida-compatible metatable 实现
-- 依赖 C 底层: Java._call, Java._staticCall, Java._new, Java._methods
-- 验证: 如果 Java._methods 不存在，打印警告但不阻断
if type(Java._methods) ~= "function" then
    print("[java_use.lua] WARNING: Java._methods not available")
end

local _methods_cache = {}

local function get_methods(cls)
    if _methods_cache[cls] then return _methods_cache[cls] end
    local ms = Java._methods(cls)
    if ms then _methods_cache[cls] = ms end
    return ms or {}
end

local function find_method_sig(cls, name, nargs)
    local ms = get_methods(cls)
    local candidates = {}
    for _, m in ipairs(ms) do
        if m.name == name then
            candidates[#candidates + 1] = m
        end
    end
    if #candidates == 0 then return nil end
    if #candidates == 1 then return candidates[1].sig, candidates[1].isStatic end
    -- 多个 overload: 按参数数量匹配
    for _, c in ipairs(candidates) do
        -- 计算签名中的参数数量
        local params = c.sig:match("%((.-)%)")
        if params then
            local count = 0
            local i = 1
            while i <= #params do
                local ch = params:sub(i, i)
                if ch == "L" then
                    i = params:find(";", i) or #params
                elseif ch == "[" then
                    i = i + 1
                    goto continue
                end
                count = count + 1
                i = i + 1
                ::continue::
            end
            if count == nargs then
                return c.sig, c.isStatic
            end
        end
    end
    -- fallback: 第一个
    return candidates[1].sig, candidates[1].isStatic
end

-- 实例对象 wrapper
local function wrap_java_obj(jptr, jclass)
    local obj = { __jptr = jptr, __jclass = jclass }
    return setmetatable(obj, {
        __index = function(self, key)
            if key == "__jptr" or key == "__jclass" then
                return rawget(self, key)
            end
            -- 返回方法 invoker
            return function(self_or_first, ...)
                local args = { ... }
                local nargs = #args
                -- self:method(args) 时 self_or_first == self
                -- 检查是否是 : 调用
                if self_or_first == obj then
                    -- : 语法
                else
                    -- . 语法, self_or_first 是第一个参数
                    table.insert(args, 1, self_or_first)
                    nargs = nargs + 1
                end
                local sig = find_method_sig(jclass, key, nargs)
                if not sig then
                    error("method not found: " .. jclass .. "." .. key)
                end
                return Java._call(jptr, jclass, key, sig, table.unpack(args))
            end
        end,
        __tostring = function(self)
            local ret = Java._call(self.__jptr, self.__jclass, "toString", "()Ljava/lang/String;")
            return ret and jstr(ret) or ("[" .. jclass .. "]")
        end,
    })
end

-- 类 wrapper (静态方法 + new)
local function wrap_java_class(cls)
    local class_obj = { __jclass = cls }
    return setmetatable(class_obj, {
        __index = function(self, key)
            if key == "__jclass" then return rawget(self, key) end
            if key == "new" then
                -- Java.use("Foo"):new(args) → Java._new
                return function(self_or_cls, ...)
                    local args = { ... }
                    local nargs = #args
                    -- 查找 <init> 签名
                    local ms = get_methods(cls)
                    local init_sig = nil
                    for _, m in ipairs(ms) do
                        if m.name == "<init>" then
                            init_sig = m.sig
                            -- 简单匹配参数数量
                            local params = m.sig:match("%((.-)%)")
                            if params then
                                local count = 0
                                local i = 1
                                while i <= #params do
                                    local ch = params:sub(i, i)
                                    if ch == "L" then i = params:find(";", i) or #params
                                    elseif ch == "[" then i = i + 1; goto cont end
                                    count = count + 1; i = i + 1; ::cont::
                                end
                                if count == nargs then break end
                            end
                        end
                    end
                    if not init_sig then
                        init_sig = "()V"
                    end
                    local jptr = Java._new(cls, init_sig, ...)
                    if jptr then
                        return wrap_java_obj(jptr, cls)
                    end
                    return nil
                end
            end
            -- 静态方法 / 实例方法 invoker
            return function(self_or_first, ...)
                local args = { ... }
                local nargs = #args
                if self_or_first == class_obj then
                    -- : 语法
                else
                    table.insert(args, 1, self_or_first)
                    nargs = nargs + 1
                end
                local sig, is_static = find_method_sig(cls, key, nargs)
                if not sig then
                    error("method not found: " .. cls .. "." .. key)
                end
                if is_static then
                    return Java._staticCall(cls, key, sig, table.unpack(args))
                else
                    error(key .. " is not static; call on an instance")
                end
            end
        end,
    })
end

-- 全局暴露 wrap_java_obj 给 C 侧返回值包装
_G._wrap_java_obj = wrap_java_obj

function Java.use(className)
    return wrap_java_class(className)
end
