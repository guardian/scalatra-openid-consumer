resolvers += "Sonatype OSS Snapshots" at "http://oss.sonatype.org/content/repositories/snapshots/"

libraryDependencies ++= Seq(
  "javax.servlet" % "servlet-api" % "2.5" % "provided",
  "org.scalatra" %% "scalatra" % "2.0.5",
  "org.openid4java" % "openid4java" % "0.9.7",
  "commons-codec" % "commons-codec" % "1.4",
  "commons-lang" % "commons-lang" % "2.5"
)


scalaVersion := "2.10.0"

crossScalaVersions ++= Seq("2.10.0")

publishArtifact := true

organization := "com.gu"

name := "scalatra-openid-consumer"

version in ThisBuild := "0.2.0"

publishTo <<= (version) { version: String =>
    val publishType = if (version.endsWith("SNAPSHOT")) "snapshots" else "releases"
    Some(
        Resolver.file(
            "guardian github " + publishType,
            file(System.getProperty("user.home") + "/guardian.github.com/maven/repo-" + publishType)
        )
    )
}
