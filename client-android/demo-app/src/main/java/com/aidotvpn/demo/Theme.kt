package com.aidotvpn.demo

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * The aidot-delivery look, in two moods.
 *
 * Dark: deep navy with an aurora gradient behind everything, cards as
 * translucent glass — a soft shadow, a faint top highlight, a hairline
 * border — and cyan as the one accent. Light: the same structure over a
 * pastel aurora, white glass, navy text.
 *
 * Every colour a screen uses comes from here, so switching the mood is
 * one value. The Android app had eight hard-coded Color constants and
 * one theme; a hospital that runs its other AIDOT apps in dark would
 * find this one the odd light square on the home screen.
 */
data class AidotPalette(
    val isDark: Boolean,
    val bgTop: Color,
    val bgBottom: Color,
    val auroraA: Color,
    val auroraB: Color,
    val glass: Color,
    val glassBorder: Color,
    val glassHighlight: Color,
    val text: Color,
    val text2: Color,
    val text3: Color,
    val accent: Color,
    val accentSoft: Color,
    val good: Color,
    val goodSoft: Color,
    val warn: Color,
    val warnSoft: Color,
    val bad: Color,
    val badSoft: Color,
    val headerBg: Color,
    val headerText: Color,
)

val DarkPalette = AidotPalette(
    isDark = true,
    bgTop = Color(0xFF0B1120),
    bgBottom = Color(0xFF0F172A),
    auroraA = Color(0x3322D3EE),
    auroraB = Color(0x338B5CF6),
    glass = Color(0x1AFFFFFF),
    glassBorder = Color(0x33FFFFFF),
    glassHighlight = Color(0x40FFFFFF),
    text = Color(0xFFE6EBF5),
    text2 = Color(0xFF9AA7C2),
    text3 = Color(0xFF6B7896),
    accent = Color(0xFF22D3EE),
    accentSoft = Color(0x2622D3EE),
    good = Color(0xFF34D399),
    goodSoft = Color(0x2634D399),
    warn = Color(0xFFFBBF24),
    warnSoft = Color(0x26FBBF24),
    bad = Color(0xFFFB7185),
    badSoft = Color(0x26FB7185),
    headerBg = Color(0xFF0B1120),
    headerText = Color(0xFFE6EBF5),
)

val LightPalette = AidotPalette(
    isDark = false,
    bgTop = Color(0xFFF0F7FF),
    bgBottom = Color(0xFFFDF2F8),
    auroraA = Color(0x4D67E8F9),
    auroraB = Color(0x4DC4B5FD),
    glass = Color(0xB3FFFFFF),
    glassBorder = Color(0x66FFFFFF),
    glassHighlight = Color(0xCCFFFFFF),
    text = Color(0xFF0F172A),
    text2 = Color(0xFF475569),
    text3 = Color(0xFF94A3B8),
    accent = Color(0xFF0891B2),
    accentSoft = Color(0x260891B2),
    good = Color(0xFF059669),
    goodSoft = Color(0x26059669),
    warn = Color(0xFFB45309),
    warnSoft = Color(0x26B45309),
    bad = Color(0xFFBE123C),
    badSoft = Color(0x26BE123C),
    headerBg = Color(0xFF0F172A),
    headerText = Color(0xFFFFFFFF),
)

val LocalPalette = staticCompositionLocalOf { DarkPalette }

/** Aurora background: two soft radial blobs over a vertical gradient. */
fun Modifier.auroraBackground(p: AidotPalette): Modifier = this
    .background(Brush.verticalGradient(listOf(p.bgTop, p.bgBottom)))
    .background(
        Brush.radialGradient(
            colors = listOf(p.auroraA, Color.Transparent),
            center = androidx.compose.ui.geometry.Offset(0.15f, 0.05f),
            radius = 900f,
        ),
    )
    .background(
        Brush.radialGradient(
            colors = listOf(p.auroraB, Color.Transparent),
            center = androidx.compose.ui.geometry.Offset(1.0f, 0.35f),
            radius = 800f,
        ),
    )

/**
 * A glass card: translucent fill, hairline border, top highlight, soft
 * shadow. The one shape every panel in the app uses.
 */
fun Modifier.glassCard(p: AidotPalette, radius: Int = 18): Modifier = this
    .shadow(if (p.isDark) 12.dp else 8.dp, RoundedCornerShape(radius.dp), clip = false,
        ambientColor = Color(0x22000000), spotColor = Color(0x33000000))
    .clip(RoundedCornerShape(radius.dp))
    .background(p.glass)
    .background(
        Brush.verticalGradient(
            0f to p.glassHighlight.copy(alpha = if (p.isDark) 0.08f else 0.6f),
            0.25f to Color.Transparent,
        ),
    )
    .border(1.dp, p.glassBorder, RoundedCornerShape(radius.dp))
