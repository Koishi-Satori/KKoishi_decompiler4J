package top.kkoishi.decomp

import top.kkoishi.cv4j.ClassReader

/**
 * The main method of this decompiler.
 *
 * @author KKoishi_
 * @param args the command line arguments.
 * @see DecompileTask.run
 * @see ClassReader.read
 */
fun main(args: Array<String>) {
    val task = DecompileTask()
    kotlin.system.exitProcess(task.run(args))
}