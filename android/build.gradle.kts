plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.linoh.android"
    compileSdk = 35

    defaultConfig {
        minSdk = 30

        // 消费者混淆规则：保留 JNI 句柄字段、native 方法
        consumerProguardFiles("consumer-rules.pro")

        // CMake 参数：传递 linoh 预编译静态库目录
        // 由 build_aar.sh 或 CI 通过 -PlinohPrebuiltDir=<path> 传入
        val linohPrebuiltDir = project.findProperty("linohPrebuiltDir")
            ?: "../build/android/\${ABI}/install"  // 默认指向 build_android.sh 产物
        externalNativeBuild {
            cmake {
                cppFlags += "-std=gnu++20"
                arguments += listOf(
                    "-DANDROID_STL=c++_shared",
                    "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON",
                    "-DLINOH_PREBUILT_DIR=${linohPrebuiltDir}"
                )
                abiFilters += listOf("arm64-v8a", "x86_64")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // 强制 NDK r27d
    ndkVersion = "27.3.13750724"

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")

    // C-4: kotlinx-coroutines 核心（api 暴露给消费者，因为 LinohCoroutines.kt 的扩展函数
    // 签名包含 suspend/Flow/CoroutineScope，消费者调用时也需要协程依赖在编译路径上）
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
}
