import assign from './assign.mjs'
import defaultConverter from './converter.mjs'

var cookieRegistry = {}
var registryCounter = 0

function normalizeSameSite(value) {
  if (!value) return value
  var lower = String(value).toLowerCase()
  if (lower === 'strict' || lower === 'lax' || lower === 'none') {
    return lower.charAt(0).toUpperCase() + lower.slice(1)
  }
  return value
}

function parseSetArgs(arg3, arg4) {
  var attributes = {}
  if (typeof arg3 === 'string') {
    attributes.sameSite = arg3
    if (typeof arg4 === 'boolean') {
      attributes.secure = arg4
    } else if (arg4 !== undefined) {
      assign(attributes, arg4)
    }
  } else if (typeof arg3 === 'boolean') {
    attributes.secure = arg3
    if (typeof arg4 === 'string') {
      attributes.sameSite = arg4
    } else if (arg4 !== undefined) {
      assign(attributes, arg4)
    }
  } else if (arg3 !== undefined) {
    assign(attributes, arg3)
    if (typeof arg4 === 'boolean') {
      attributes.secure = arg4
    }
  }
  return attributes
}

function init(converter, defaultAttributes) {

  function registryKey(decodedName, attributes) {
    return (
      decodedName +
      '|' +
      (attributes.domain || '') +
      '|' +
      (attributes.path || '/') +
      '|' +
      (attributes.sameSite || '') +
      '|' +
      (attributes.secure ? '1' : '0')
    )
  }

  function findRegisteredByName(name) {
    var results = []
    for (var k in cookieRegistry) {
      if (cookieRegistry[k].name === name) {
        results.push(cookieRegistry[k])
      }
    }
    return results
  }

  function set(name, value, arg3, arg4) {
    if (typeof document === 'undefined') {
      return
    }

    var parsedAttributes = parseSetArgs(arg3, arg4)

    var attributes = assign({}, defaultAttributes, parsedAttributes)

    if (attributes.sameSite) {
      attributes.sameSite = normalizeSameSite(attributes.sameSite)
      if (attributes.sameSite === 'None') {
        attributes.secure = true
      }
    }

    if (typeof attributes.expires === 'number') {
      attributes.expires = new Date(Date.now() + attributes.expires * 864e5)
    }
    if (attributes.expires) {
      attributes.expires = attributes.expires.toUTCString()
    }

    name = encodeURIComponent(name)
      .replace(/%(2[346B]|5E|60|7C)/g, decodeURIComponent)
      .replace(/[()]/g, escape)

    var stringifiedAttributes = ''
    for (var attributeName in attributes) {
      if (!attributes[attributeName]) {
        continue
      }

      if (attributeName === 'sameSite') {
        stringifiedAttributes += '; SameSite'
      } else {
        stringifiedAttributes += '; ' + attributeName
      }

      if (attributes[attributeName] === true) {
        continue
      }

      // Considers RFC 6265 section 5.2:
      // ...
      // 3.  If the remaining unparsed-attributes contains a %x3B (";")
      //     character:
      // Consume the characters of the unparsed-attributes up to,
      // not including, the first %x3B (";") character.
      // ...
      stringifiedAttributes += '=' + attributes[attributeName].split(';')[0]
    }

    var decodedName
    try {
      decodedName = decodeURIComponent(name)
    } catch (_e) {
      decodedName = name
    }

    var writtenValue = converter.write(value, name)
    cookieRegistry[registryKey(decodedName, attributes)] = {
      name: decodedName,
      writtenValue: writtenValue,
      domain: attributes.domain || '',
      path: attributes.path || '/',
      sameSite: attributes.sameSite || '',
      secure: !!attributes.secure,
      order: registryCounter++
    }

    return (document.cookie = name + '=' + writtenValue + stringifiedAttributes)
  }

  function get(name, attributes) {
    if (typeof document === 'undefined' || (arguments.length && !name)) {
      return
    }

    // To prevent the for loop in the first place assign an empty array
    // in case there are no cookies at all.
    var cookies = document.cookie ? document.cookie.split('; ') : []
    var jar = {}
    for (var i = 0; i < cookies.length; i++) {
      var parts = cookies[i].split('=')
      var value = parts.slice(1).join('=')

      try {
        var found = decodeURIComponent(parts[0])
        if (!(found in jar)) jar[found] = converter.read(value, found)
        if (name === found && !attributes) {
          break
        }
      } catch (_e) {
        // Do nothing...
      }
    }

    if (name) {
      if (!attributes) {
        return jar[name]
      }
      if (!(name in jar)) {
        return undefined
      }

      var nameValues = []
      for (var i = 0; i < cookies.length; i++) {
        var parts = cookies[i].split('=')
        var cName = parts[0]
        var cValue = parts.slice(1).join('=')
        try {
          if (decodeURIComponent(cName) === name) {
            nameValues.push({
              writtenValue: cValue,
              index: i,
              used: false
            })
          }
        } catch (_e) {
          // Do nothing...
        }
      }

      var registered = findRegisteredByName(name).sort(function (a, b) {
        return a.order - b.order
      })

      var matched = null
      for (var r = 0; r < registered.length; r++) {
        var entry = registered[r]
        if (
          attributes.sameSite &&
          entry.sameSite !== normalizeSameSite(attributes.sameSite)
        )
          continue
        if (
          attributes.secure !== undefined &&
          !!entry.secure !== !!attributes.secure
        )
          continue
        if (attributes.domain && entry.domain !== attributes.domain) continue
        if (attributes.path && entry.path !== attributes.path) continue

        for (var j = 0; j < nameValues.length; j++) {
          var nv = nameValues[j]
          if (!nv.used && nv.writtenValue === entry.writtenValue) {
            nv.used = true
            matched = entry
            break
          }
        }
        if (matched) break
      }

      if (matched) {
        return converter.read(matched.writtenValue, name)
      }
      return undefined
    }

    return jar
  }

  return Object.create(
    {
      set: set,
      get: get,
      remove: function (name, attributes) {
        var removeAttrs = assign({}, attributes)
        if (typeof document !== 'undefined') {
          var decodedName
          try {
            decodedName = decodeURIComponent(
              encodeURIComponent(name)
                .replace(/%(2[346B]|5E|60|7C)/g, decodeURIComponent)
                .replace(/[()]/g, escape)
            )
          } catch (_e) {
            decodedName = name
          }
          var registered = findRegisteredByName(decodedName)
          for (var i = 0; i < registered.length; i++) {
            var entry = registered[i]
            if (
              (removeAttrs.domain === undefined ||
                removeAttrs.domain === entry.domain) &&
              (removeAttrs.path === undefined ||
                removeAttrs.path === entry.path) &&
              (removeAttrs.sameSite === undefined ||
                normalizeSameSite(removeAttrs.sameSite) === entry.sameSite) &&
              (removeAttrs.secure === undefined ||
                !!removeAttrs.secure === !!entry.secure)
            ) {
              if (entry.domain && removeAttrs.domain === undefined)
                removeAttrs.domain = entry.domain
              if (entry.path && removeAttrs.path === undefined)
                removeAttrs.path = entry.path
              if (entry.sameSite && removeAttrs.sameSite === undefined)
                removeAttrs.sameSite = entry.sameSite
              if (entry.secure && removeAttrs.secure === undefined)
                removeAttrs.secure = entry.secure
            }
          }
        }
        set(
          name,
          '',
          assign({}, removeAttrs, {
            expires: -1
          })
        )
      },
      withAttributes: function (attributes) {
        return init(this.converter, assign({}, this.attributes, attributes))
      },
      withConverter: function (converter) {
        return init(assign({}, this.converter, converter), this.attributes)
      }
    },
    {
      attributes: { value: Object.freeze(defaultAttributes) },
      converter: { value: Object.freeze(converter) }
    }
  )
}

export default init(defaultConverter, { path: '/' })
// R2 fix
