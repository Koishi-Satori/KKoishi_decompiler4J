@file:Suppress("MemberVisibilityCanBePrivate")

package top.kkoishi.decomp

import top.kkoishi.cv4j.ClassReader
import top.kkoishi.cv4j.DecompilerException
import top.kkoishi.decomp.classfile.FileProcessor
import top.kkoishi.proc.json.JsonParser
import top.kkoishi.proc.json.MappedJsonObject
import java.io.PrintWriter
import java.nio.file.Path
import java.text.DateFormat
import java.text.MessageFormat
import java.util.*
import kotlin.collections.ArrayDeque
import kotlin.io.path.readText
import kotlin.reflect.KClass

object Utils {
    @JvmStatic
    val jsonMaps = HashMap<String, MappedJsonObject>()

    @JvmStatic
    var jsonParser: JsonParser? = null

    @JvmStatic
    val nl = System.getProperty("line.separator")

    @JvmStatic
    fun getLocale(): Locale {
        var o = jsonMaps["property"]
        if (o == null) {
            jsonParser = JsonParser(Path.of("./data/property.json").readText())
            jsonParser!!.parse()
            o = MappedJsonObject.cast(jsonParser!!.result(), HashMap::class.java)
        }
        jsonMaps["property"] = o!!
        return Locale(o["current_locale"] as String)
    }

    @JvmStatic
    private val classAccessFlags: Array<Pair<Int, String>> = arrayOf(
        ClassReader.ACC_MODULE to "module",
        ClassReader.ACC_ENUM to "enum ",
        ClassReader.ACC_ANNOTATION to "@interface ",
        ClassReader.ACC_SYNTHETIC to "",
        ClassReader.ACC_ABSTRACT to "abstract ",
        ClassReader.ACC_INTERFACE to "interface ",
        ClassReader.ACC_SUPER to "",
        ClassReader.ACC_FINAL to "final ",
        ClassReader.ACC_PUBLIC to "public "
    )

    @JvmStatic
    fun parseClassAccessFlags(accessFlags: Int): String {
        var cpy = accessFlags
        val buf = StringBuilder()
        classAccessFlags.forEach { with(it) {
            if (cpy >= first) {
                cpy -= first
                buf.append(second)
            }
        } }
        return buf.toString()
    }
}

object Options {
    enum class DisplayLevel {
        PUBLIC,
        PROTECTED,
        PACKAGE,
        PRIVATE;
    }

    @JvmStatic
    val recognizedOptions: Array<Option> = arrayOf(
        object : Option(false, "-help", "-h", "-?") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                help = true
            }
        },
        object : Option(false, "-version") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                version = true
            }
        },
        object : Option(false, "-sysinfo") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                sysinfo = true
            }
        },
        object : Option(false, "-constants") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                constants = true
            }
        },
        object : Option(false, "-private", "-p") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                if (level.ordinal < DisplayLevel.PRIVATE.ordinal) {
                    level = DisplayLevel.PRIVATE
                }
            }
        },
        object : Option(false, "-package") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                if (level.ordinal < DisplayLevel.PACKAGE.ordinal) {
                    level = DisplayLevel.PACKAGE
                }
            }
        },
        object : Option(false, "-protected") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                if (level.ordinal < DisplayLevel.PROTECTED.ordinal) {
                    level = DisplayLevel.PROTECTED
                }
            }
        },
        object : Option(false, "-public") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                if (level.ordinal < DisplayLevel.PUBLIC.ordinal) {
                    level = DisplayLevel.PUBLIC
                }
            }
        },
        object : Option(false, "-l") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                lines_locals = true
            }
        },
        object : Option(false, "-verbose", "-v") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                verbose = true
            }
        },
        object : Option(false, "-instruction", "-inst", "-i") {
            override fun process(task: DecompileTask, opt: String, arg: String?) {
                instructions = true
            }

        })

    @JvmStatic
    var help = false

    @JvmStatic
    var version = false

    @JvmStatic
    var sysinfo = false

    @JvmStatic
    var constants = false

    @JvmStatic
    var level: DisplayLevel = DisplayLevel.PUBLIC

    @JvmStatic
    var lines_locals = false

    @JvmStatic
    var verbose = false

    @JvmStatic
    var instructions = false
}

class ResourceException : Exception {
    constructor() : super()
    constructor(message: String?) : super(message)
    constructor(message: String?, cause: Throwable?) : super(message, cause)
    constructor(cause: Throwable?) : super(cause)
}

abstract class Option(val hasArg: Boolean, vararg _aliases: String) {
    @Suppress("UNCHECKED_CAST")
    val aliases: Array<String> = _aliases as Array<String>
    abstract fun process(task: DecompileTask, opt: String, arg: String?)
    open fun matches(opt: String): Boolean {
        for (e in aliases) if (opt == e) return true
        return false
    }
}

class LogWriter constructor(
    val clz: KClass<*>,
    var logLevel: System.Logger.Level,
    val log: PrintWriter,
    val useFullName: Boolean,
    val dateFormat: DateFormat,
) :
    System.Logger {

    override fun getName(): String = "Kecompile.logger:${clz.qualifiedName}"

    override fun isLoggable(level: System.Logger.Level): Boolean = level >= logLevel

    override fun log(level: System.Logger.Level, bundle: ResourceBundle?, key: String?, thrown: Throwable?) {
        if (isLoggable(level)) {
            info()
            if (thrown == null) {
                if (bundle != null && key != null)
                    try {
                        log.println(bundle.getString(key))
                    } catch (e: Exception) {
                        e.printStackTrace(log)
                    }
                else
                    log.println(key)
            } else {
                if (bundle == null && key == null)
                    thrown.printStackTrace(log)
            }
        }
    }

    @Suppress("NOTHING_TO_INLINE")
    private inline fun info() {
        if (useFullName) {
            log.print(name)
        }
        log.print("[${dateFormat.format(Date(System.currentTimeMillis()))}][${Thread.currentThread()}/$logLevel]")
    }

    override fun log(level: System.Logger.Level, bundle: ResourceBundle?, format: String?, vararg params: Any?) {
        if (isLoggable(level)) {
            info()
            if (bundle != null && format != null) {
                try {
                    log.println(MessageFormat.format(bundle.getString(format), params))
                } catch (e: Exception) {
                    e.printStackTrace(log)
                }
            } else {
                if (format == null)
                    log.println("null")
                else
                    log.println(MessageFormat.format(format, params))
            }
        }
    }
}

open class Context {
    protected val map: HashMap<KClass<*>, Any> = HashMap()

    @Suppress("UNCHECKED_CAST")
    operator fun <T> get(key: KClass<T>): T? where T : Any = map[key] as T?

    @Suppress("UNCHECKED_CAST")
    fun <T> put(key: KClass<T>, value: T): T where T : Any = map.put(key, value) as T

    operator fun <T> set(key: KClass<T>, value: T): T where T : Any = put(key, value)
}

interface Messages {
    fun getMessage(key: String, vararg args: Any?): String

    fun getMessage(locale: Locale, key: String, vararg args: Any?): String
}

class DecompileTask @JvmOverloads constructor(val locale: Locale = Utils.getLocale()) : Context(), Messages {
    private val classes: ArrayDeque<String> = ArrayDeque(8)
    val bundles: HashMap<Locale, ResourceBundle> = HashMap()
    val processer = FileProcessor(this)

    class BadArg internal constructor(
        internal val key: String,
        msg: String,
        vararg _args: Any?,
    ) : Exception(msg) {
        @Suppress("UNCHECKED_CAST")
        internal val args: Array<String> = _args as Array<String>
        internal var needShowUsage = false

        fun showUsage(v: Boolean): BadArg {
            needShowUsage = v
            return this
        }
    }

    companion object {
        /**
         * Compilation completed with no errors.
         */
        const val EXIT_OK = 0

        /**
         * Completed but reported errors.
         */
        const val EXIT_ERROR = 1

        /**
         * Bad command-line arguments
         */
        const val EXIT_CMD_ERR = 2

        /**
         * System error or resource exhaustion.
         */
        const val EXIT_SYSTEM_ERR = 3

        /**
         * Compiler terminated abnormally
         */
        const val EXIT_ABNORMAL = 4

        @JvmStatic
        fun instance(context: Context): DecompileTask = context[DecompileTask::class] ?: DecompileTask()
    }

    init {
        map[DecompileTask::class] = this
        map[Messages::class] = this
    }

    override fun getMessage(key: String, vararg args: Any?): String = getMessage(locale, key, *args)

    override fun getMessage(locale: Locale, key: String, vararg args: Any?): String {
        var bundle = bundles[locale]
        if (bundle == null) {
            try {
                bundle = ResourceBundle.getBundle("kecompile", locale)
            } catch (e: Exception) {
                throw ResourceException(e)
            }
            bundles[locale] = bundle
        }
        return MessageFormat.format(bundle!!.getString(key), *args)
    }

    fun run(args: Array<String>): Int {
        try {
            handleArguments(args)
        } catch (de: DecompilerException) {
            de.printStackTrace(System.err)
            reportError("err.files.decompile.failed")
            return EXIT_ABNORMAL
        } catch (ba: BadArg) {
            if (ba.needShowUsage)
                showUsage()
            reportError(ba.key, *ba.args)
            return EXIT_CMD_ERR
        } catch (re: ResourceException) {
            re.printStackTrace(System.err)
            return EXIT_SYSTEM_ERR
        } catch (oe: IndexOutOfBoundsException) {
            oe.printStackTrace(System.err)
            return EXIT_SYSTEM_ERR
        } catch (e: Exception) {
            e.printStackTrace(System.err)
            return EXIT_ERROR
        }
        return EXIT_OK
    }

    fun showUsage() {

    }

    fun handleArguments(args: Array<String>) = handleArguments(args.iterator(), true)

    fun handleArguments(args: Iterator<String>, hasClasses: Boolean) {
        while (args.hasNext()) {
            val arg = args.next()
            if (arg.startsWith("-")) {
                handleArgument(arg, args)
            } else if (hasClasses) {
                classes.addLast(arg)
            } else throw getBadArg("err.options.unknown", arg).showUsage(true)
        }
        if (classes.isNotEmpty())
            classes.forEach(processer::processFile)
    }

    fun handleArgument(arg: String, rest: Iterator<String>) {
        for (o in Options.recognizedOptions) {
            if (o.matches(arg)) {
                if (o.hasArg) {
                    if (!rest.hasNext()) {
                        throw getBadArg("err.args.missing", arg).showUsage(true)
                    }
                    o.process(this, arg, rest.next())
                } else
                    o.process(this, arg, null)
                return
            }
        }
        try {
            processer.process(arg, rest)
        } catch (e: IllegalArgumentException) {
            throw getBadArg("err.args.invalid.use", arg).showUsage(true)
        } catch (de: DecompilerException) {
            throw de
        }
        throw getBadArg("err.options.unknown", arg)
    }

    fun getBadArg(key: String, vararg args: String?) = BadArg(key, getMessage(key, args), args)

    fun reportError(errKey: String, vararg args: String) = System.err.println(getMessage(errKey, *args))

    fun report(msg: String) = System.out.println(msg.replace("\n", Utils.nl, false).replace("\t", "    ", false))
}
