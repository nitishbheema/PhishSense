import { useEffect, useRef, useState, useCallback } from 'react'
import tracker from '../utils/behaviorTracker'

/**
 * useBehaviorTracker
 * Drop this into any page to start tracking.
 *
 * @param {string} pageLabel  - e.g. 'legit-login' | 'phishing-demo'
 * @param {object} options
 *   snapshotInterval  - ms between live snapshot updates (default 2000)
 *   onAnomaly         - callback(snapshot) when anomalyScore > threshold
 *   anomalyThreshold  - score 0-100 to trigger onAnomaly (default 50)
 */
export function useBehaviorTracker(pageLabel = 'page', options = {}) {
  const {
    snapshotInterval = 2000,
    onAnomaly = null,
    anomalyThreshold = 50,
  } = options

  const [snapshot, setSnapshot] = useState(null)
  const intervalRef = useRef(null)

  useEffect(() => {
    tracker.start(pageLabel)

    intervalRef.current = setInterval(() => {
      const snap = tracker.getSnapshot()
      setSnapshot(snap)
      if (onAnomaly && snap && snap.anomalyScore >= anomalyThreshold) {
        onAnomaly(snap)
      }
    }, snapshotInterval)

    return () => {
      clearInterval(intervalRef.current)
      tracker.stop()
    }
  }, [pageLabel])

  const stopAndGet = useCallback(() => {
    clearInterval(intervalRef.current)
    return tracker.stop()
  }, [])

  return { snapshot, stopAndGet }
}

export default useBehaviorTracker
