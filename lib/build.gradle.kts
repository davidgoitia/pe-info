import java.text.SimpleDateFormat
import java.util.*

/*
 * This file was generated by the Gradle 'init' task.
 *
 * This generated file contains a sample Java library project to get you started.
 * For more details on building Java & JVM projects, please refer to https://docs.gradle.org/8.10.2/userguide/building_java_projects.html in the Gradle documentation.
 */

plugins {
    // Apply the java-library plugin for API and implementation separation.
    `java-library`
    `maven-publish`
    signing
    id("io.freefair.lombok") version "8.10.2"
}

description = "PE file info extractor"
group = "es.goitia.pe"
version = "0.0.1"
var mainClassName = "es.goitia.pe.PEInfo"

repositories {
    // Use Maven Central for resolving dependencies.
    mavenCentral()
}

dependencies {
    // Use JUnit Jupiter for testing.
    testImplementation(libs.junit.jupiter)

    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // This dependency is exported to consumers, that is to say found on their compile classpath.
    api(libs.commons.math3)

    // This dependency is used internally, and not exposed to consumers on their own compile classpath.
    implementation(libs.guava)
}

// Apply a specific Java toolchain to ease working on different environments.
java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(8)
    }
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])

            pom {
                name.set("PE Info")
//                description.set("An example of a Gradle project using Kotlin DSL")
                url.set("https://github.com/davidgoitia/pe-info")

                licenses {
                    license {
                        name.set("The MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("davidgoitia")
                        name.set("David Goitia")
                        email.set("david@goitia.es")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/davidgoitia/pe-info.git")
                    developerConnection.set("scm:git:ssh://github.com/davidgoitia/pe-info.git")
                    url.set("https://github.com/davidgoitia/pe-info")
                }
            }
        }
    }

    repositories {
//        maven {
//            name = "myRepo"
//            url = uri(layout.buildDirectory.dir("repo"))
//        }
//        maven {
//            name = "GitHubPackages"
//            url = uri("https://maven.pkg.github.com/username/repo")
//            credentials {
//                username = project.findProperty("gpr.user") as String? ?: System.getenv("USERNAME_GITHUB")
//                password = project.findProperty("gpr.token") as String? ?: System.getenv("TOKEN_GITHUB")
//            }
//        }
        maven {
            name = "OSSRH"
            url = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("OSS_MAVEN_USERNAME")
                password = System.getenv("OSS_MAVEN_PASSWORD")
            }
        }
    }
}

signing {
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])
}

tasks.jar {
        manifest.attributes(
            mapOf(
                "Application-Name" to project.name,
                "Application-Version" to project.version,
                "Build-Timestamp" to SimpleDateFormat("yyyy/MM/dd HH:mm:ss z").format(Date()),
//                "Build-Revision" to versioning.info.commit,
                "Created-By" to "Gradle ${gradle.gradleVersion}",
                "Build-Jdk" to "${System.getProperty("java.version")} (${System.getProperty("java.vendor")} ${System.getProperty("java.vm.version")})",
                "Build-OS" to "${System.getProperty("os.name")} ${System.getProperty("os.arch")} ${System.getProperty("os.version")}",
                "Main-Class" to mainClassName,
//                "Class-Path" to configurations.runtimeClasspath.reles.joinToString(" ") { it.name }
            )
        )
}

tasks.named<Test>("test") {
    // Use JUnit Platform for unit tests.
    useJUnitPlatform()
}
