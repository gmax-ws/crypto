name := "crypto"

version := "0.1"

scalaVersion := "2.13.4"

libraryDependencies ++= Seq(
  "commons-codec" % "commons-codec" % "1.15",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.64",
  "com.google.guava" % "guava" % "30.1-jre",
  "com.typesafe" % "config" % "1.4.1"
)
