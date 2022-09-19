package top.kkoishi.decomp

fun main(args: Array<String>) {
    val task = DecompileTask()
    kotlin.system.exitProcess(task.run(args))
}