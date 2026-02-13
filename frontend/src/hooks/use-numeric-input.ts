import { useCallback, type ChangeEvent, type KeyboardEvent, type FocusEvent } from 'react'

interface NumericInputHandlersOptions {
  /** Minimum allowed value (inclusive) */
  min?: number
  /** Maximum allowed value (inclusive) */
  max?: number
  /** Called with the parsed value or undefined when cleared */
  onCommit: (value: number | undefined) => void
  /** Update the display string state */
  setDisplay: (value: string) => void
}

/**
 * Creates onChange/onKeyDown/onBlur handlers for a numeric text input.
 * Eliminates the duplicated parseFloat/round/validate pattern across form fields.
 *
 * @example
 * const handlers = useNumericInputHandlers({
 *   min: 0, max: 100,
 *   onCommit: field.onChange,
 *   setDisplay: setMinPriceDisplay,
 * })
 * <Input value={minPriceDisplay} {...handlers} />
 */
export function useNumericInputHandlers({ min = 0, max, onCommit, setDisplay }: NumericInputHandlersOptions) {
  const commitValue = useCallback((rawValue: string) => {
    const val = rawValue.trim()
    if (val === '') {
      onCommit(undefined)
      setDisplay('')
      return
    }
    const num = parseFloat(val)
    if (!isNaN(num) && num >= min && (max === undefined || num <= max)) {
      const rounded = Math.round(num * 100) / 100
      onCommit(rounded)
      setDisplay(rounded.toString())
    } else {
      onCommit(undefined)
      setDisplay('')
    }
  }, [min, max, onCommit, setDisplay])

  const onChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    setDisplay(e.target.value)
  }, [setDisplay])

  const onKeyDown = useCallback((e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      commitValue(e.currentTarget.value)
    }
  }, [commitValue])

  const onBlur = useCallback((e: FocusEvent<HTMLInputElement>) => {
    commitValue(e.target.value)
  }, [commitValue])

  return { onChange, onKeyDown, onBlur }
}
