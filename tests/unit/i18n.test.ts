import { formatCurrency, formatDate, formatNumber } from '../../src/utils/localization';

describe('Localization Utilities', () => {
  test('formatCurrency should format correctly', () => {
    const result = formatCurrency(100.50, 'en', 'USD');
    expect(result).toContain('100.50');
  });

  test('formatDate should format correctly', () => {
    const date = new Date('2024-01-01');
    const result = formatDate(date, 'en');
    expect(result).toBeDefined();
  });

  test('formatNumber should format correctly', () => {
    const result = formatNumber(1234567.89, 'en');
    expect(result).toContain('1,234,567');
  });
});
