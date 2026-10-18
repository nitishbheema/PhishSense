// ─────────────────────────────────────────────
//  PhishGuard Behavioral Tracker
//  Collects: mouse, keyboard, click, scroll,
//            typing rhythm, idle time, redirects
// ─────────────────────────────────────────────

const SESSION_KEY = 'pg_behavior_session'

function createSession() {
  return {
    sessionId: crypto.randomUUID(),
    startTime: Date.now(),
    url: window.location.href,
    userAgent: navigator.userAgent,

    // Mouse data
    mousePath: [],           // [{x, y, t}]
    mouseSpeed: [],          // px/ms samples
    mouseJitter: 0,          // abrupt direction changes
    hoverEvents: [],         // [{target, duration}]

    // Keyboard data
    keystrokes: [],          // [{key, downAt, upAt, dwellMs}]
    typingDelays: [],        // ms between keystrokes
    typingSpeed: 0,          // chars per second (avg)
    backspaceCount: 0,
    pasteCount: 0,

    // Click data
    clicks: [],              // [{x, y, target, t, button}]
    doubleClicks: 0,
    rapidClicks: 0,          // clicks < 300ms apart
    clickPositions: [],

    // Scroll data
    scrollEvents: [],        // [{scrollY, t}]
    scrollDepth: 0,          // max % scrolled
    scrollSpeed: [],

    // Form interaction
    formFocusEvents: [],     // [{field, t}]
    fieldFillTimes: {},      // {fieldName: ms}
    formSubmitTime: null,

    // Timing
    idlePeriods: [],         // [{start, end}]
    totalActiveMs: 0,
    pageLoadToFirstAction: null,

    // Anomalies (computed)
    anomalyScore: 0,
    flags: [],
  }
}

class BehaviorTracker {
  constructor() {
    this.session = null
    this.listeners = []
    this.isTracking = false
    this._lastMousePos = null
    this._lastMouseTime = null
    this._lastClickTime = null
    this._lastKeystrokeTime = null
    this._lastScrollY = null
    this._lastScrollTime = null
    this._lastActiveTime = null
    this._idleStart = null
    this._idleThreshold = 3000 // 3s = idle
    this._idleTimer = null
    this._fieldFocusTime = {}
    this._keyDownMap = {}
  }

  start(pageLabel = 'unknown') {
    if (this.isTracking) return
    this.session = createSession()
    this.session.pageLabel = pageLabel
    this.isTracking = true
    this._lastActiveTime = Date.now()
    this._attachListeners()
    return this.session.sessionId
  }

  stop() {
    if (!this.isTracking) return null
    this.isTracking = false
    this._detachListeners()
    this._finalizeSession()
    return this.getSnapshot()
  }


  getSnapshot() {
    if (!this.session) return null
    this._computeAnomalyScore()
    return { ...this.session }
  }

  // ── Event Handlers ──────────────────────────

  _onMouseMove = (e) => {
    const now = Date.now()
    const { clientX: x, clientY: y } = e

    if (this.session.pageLoadToFirstAction === null) {
      this.session.pageLoadToFirstAction = now - this.session.startTime
    }

    // Sample every 50ms to avoid flooding
    if (!this._lastMouseTime || now - this._lastMouseTime > 50) {
      this.session.mousePath.push({ x, y, t: now })

      if (this._lastMousePos) {
        const dx = x - this._lastMousePos.x
        const dy = y - this._lastMousePos.y
        const dist = Math.sqrt(dx * dx + dy * dy)
        const dt = now - this._lastMouseTime
        const speed = dt > 0 ? dist / dt : 0
        this.session.mouseSpeed.push(parseFloat(speed.toFixed(3)))

        // Jitter: abrupt direction change > 90 degrees
        if (this.session.mousePath.length > 2) {
          const prev = this.session.mousePath[this.session.mousePath.length - 3]
          const v1 = { x: this._lastMousePos.x - prev.x, y: this._lastMousePos.y - prev.y }
          const v2 = { x: dx, y: dy }
          const dot = v1.x * v2.x + v1.y * v2.y
          const mag1 = Math.sqrt(v1.x ** 2 + v1.y ** 2)
          const mag2 = Math.sqrt(v2.x ** 2 + v2.y ** 2)
          if (mag1 > 0 && mag2 > 0) {
            const cos = dot / (mag1 * mag2)
            const angle = Math.acos(Math.max(-1, Math.min(1, cos))) * (180 / Math.PI)
            if (angle > 90) this.session.mouseJitter++
          }
        }
      }

      this._lastMousePos = { x, y }
      this._lastMouseTime = now
    }

    this._resetIdle()
  }

  _onClick = (e) => {
    const now = Date.now()
    const target = e.target?.tagName + (e.target?.type ? `[${e.target.type}]` : '')

    this.session.clicks.push({
      x: e.clientX, y: e.clientY,
      target, t: now, button: e.button,
    })
    this.session.clickPositions.push([e.clientX, e.clientY])

    if (this._lastClickTime) {
      const gap = now - this._lastClickTime
      if (gap < 300) this.session.rapidClicks++
    }
    this._lastClickTime = now
    this._resetIdle()
  }

  _onDblClick = () => {
    this.session.doubleClicks++
  }

  _onKeyDown = (e) => {
    const now = Date.now()
    this._keyDownMap[e.code] = now

    if (this._lastKeystrokeTime) {
      const delay = now - this._lastKeystrokeTime
      this.session.typingDelays.push(delay)
    }
    this._lastKeystrokeTime = now

    if (e.key === 'Backspace') this.session.backspaceCount++
    this._resetIdle()
  }

  _onKeyUp = (e) => {
    const now = Date.now()
    const downAt = this._keyDownMap[e.code]
    if (downAt) {
      const dwellMs = now - downAt
      this.session.keystrokes.push({
        key: e.key.length === 1 ? '•' : e.key, // mask actual chars
        downAt, upAt: now, dwellMs,
      })
      delete this._keyDownMap[e.code]
    }
  }

  _onPaste = () => {
    this.session.pasteCount++
  }

  _onScroll = () => {
    const now = Date.now()
    const scrollY = window.scrollY
    const maxScroll = document.documentElement.scrollHeight - window.innerHeight
    const pct = maxScroll > 0 ? (scrollY / maxScroll) * 100 : 0

    this.session.scrollEvents.push({ scrollY, t: now })
    if (pct > this.session.scrollDepth) this.session.scrollDepth = parseFloat(pct.toFixed(1))

    if (this._lastScrollTime) {
      const dt = now - this._lastScrollTime
      const dy = Math.abs(scrollY - (this._lastScrollY || 0))
      const speed = dt > 0 ? dy / dt : 0
      this.session.scrollSpeed.push(parseFloat(speed.toFixed(3)))
    }
    this._lastScrollY = scrollY
    this._lastScrollTime = now
    this._resetIdle()
  }

  _onFocus = (e) => {
    const name = e.target?.name || e.target?.id || e.target?.placeholder || 'unknown'
    const now = Date.now()
    this._fieldFocusTime[name] = now
    this.session.formFocusEvents.push({ field: name, t: now })
  }

  _onBlur = (e) => {
    const name = e.target?.name || e.target?.id || e.target?.placeholder || 'unknown'
    const focusAt = this._fieldFocusTime[name]
    if (focusAt) {
      const duration = Date.now() - focusAt
      this.session.fieldFillTimes[name] = duration
      delete this._fieldFocusTime[name]
    }
  }

  _onSubmit = () => {
    this.session.formSubmitTime = Date.now() - this.session.startTime
  }

  _onVisibilityChange = () => {
    if (document.hidden) {
      this._idleStart = Date.now()
    } else if (this._idleStart) {
      this.session.idlePeriods.push({ start: this._idleStart, end: Date.now() })
      this._idleStart = null
    }
  }

  // ── Idle detection ───────────────────────────

  _resetIdle() {
    if (this._idleStart) {
      this.session.idlePeriods.push({ start: this._idleStart, end: Date.now() })
      this._idleStart = null
    }
    clearTimeout(this._idleTimer)
    this._idleTimer = setTimeout(() => {
      this._idleStart = Date.now()
    }, this._idleThreshold)
    this._lastActiveTime = Date.now()
  }

  // ── Attach / Detach ──────────────────────────

  _attachListeners() {
    const opts = { passive: true }
    document.addEventListener('mousemove', this._onMouseMove, opts)
    document.addEventListener('click', this._onClick, opts)
    document.addEventListener('dblclick', this._onDblClick, opts)
    document.addEventListener('keydown', this._onKeyDown)
    document.addEventListener('keyup', this._onKeyUp)
    document.addEventListener('paste', this._onPaste, opts)
    document.addEventListener('scroll', this._onScroll, opts)
    document.addEventListener('visibilitychange', this._onVisibilityChange)
    document.addEventListener('focus', this._onFocus, true)
    document.addEventListener('blur', this._onBlur, true)
    document.addEventListener('submit', this._onSubmit, true)
  }

  _detachListeners() {
    document.removeEventListener('mousemove', this._onMouseMove)
    document.removeEventListener('click', this._onClick)
    document.removeEventListener('dblclick', this._onDblClick)
    document.removeEventListener('keydown', this._onKeyDown)
    document.removeEventListener('keyup', this._onKeyUp)
    document.removeEventListener('paste', this._onPaste)
    document.removeEventListener('scroll', this._onScroll)
    document.removeEventListener('visibilitychange', this._onVisibilityChange)
    document.removeEventListener('focus', this._onFocus, true)
    document.removeEventListener('blur', this._onBlur, true)
    document.removeEventListener('submit', this._onSubmit)
    clearTimeout(this._idleTimer)
  }

  // ── Finalize + Feature Extraction ────────────

  _finalizeSession() {
    const s = this.session
    const now = Date.now()
    s.totalActiveMs = now - s.startTime

    // Compute avg typing speed (chars/sec)
    if (s.typingDelays.length > 1) {
      const avgDelay = s.typingDelays.reduce((a, b) => a + b, 0) / s.typingDelays.length
      s.typingSpeed = avgDelay > 0 ? parseFloat((1000 / avgDelay).toFixed(2)) : 0
    }

    this._computeAnomalyScore()
  }

  _computeAnomalyScore() {
    const s = this.session
    if (!s) return
    let score = 0
    const flags = []

    // 1. Paste into password field (big red flag)
    if (s.pasteCount > 0) {
      score += 20
      flags.push('Password pasted (not typed)')
    }

    // 2. Extremely fast form fill (bot-like < 2s)
    if (s.formSubmitTime !== null && s.formSubmitTime < 2000) {
      score += 25
      flags.push('Form filled impossibly fast (<2s)')
    }

    // 3. No mouse movement at all
    if (s.mousePath.length === 0 && s.clicks.length > 0) {
      score += 15
      flags.push('Clicks with no mouse movement (automated?)')
    }

    // 4. High mouse jitter (bot random movement)
    const jitterRatio = s.mousePath.length > 0 ? s.mouseJitter / s.mousePath.length : 0
    if (jitterRatio > 0.4) {
      score += 15
      flags.push('Erratic mouse movement pattern')
    }

    // 5. Uniform typing delay (bot typing at fixed interval)
    if (s.typingDelays.length > 4) {
      const mean = s.typingDelays.reduce((a, b) => a + b, 0) / s.typingDelays.length
      const variance = s.typingDelays.reduce((a, b) => a + (b - mean) ** 2, 0) / s.typingDelays.length
      const stddev = Math.sqrt(variance)
      if (stddev < 20 && mean < 200) {
        score += 20
        flags.push('Robotic uniform typing rhythm')
      }
    }

    // 6. Rapid clicks (multiple clicks < 300ms)
    if (s.rapidClicks > 3) {
      score += 10
      flags.push('Abnormal rapid clicking behavior')
    }

    // 7. Too many backspaces (confused user / testing)
    if (s.backspaceCount > 15) {
      score += 5
      flags.push('Excessive backspacing detected')
    }

    // 8. Page time too short
    if (s.totalActiveMs < 1500 && s.formSubmitTime !== null) {
      score += 15
      flags.push('Submitted form without reading page')
    }

    // 9. No scroll on long page
    if (s.scrollDepth < 5 && document.documentElement.scrollHeight > window.innerHeight * 1.5) {
      score += 5
      flags.push('No scrolling on long page')
    }

    s.anomalyScore = Math.min(100, score)
    s.flags = flags
  }
}

// Singleton instance
export const tracker = new BehaviorTracker()
export default tracker
