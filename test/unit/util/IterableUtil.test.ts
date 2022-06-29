import { concatIterables, filterIterable, mapIterable, reduceIterable } from '../../../src/util/IterableUtil';

describe('IterableUtil', (): void => {
  describe('#mapIterable', (): void => {
    it('maps the values to a new iterable.', async(): Promise<void> => {
      const input = [ 1, 2, 3 ];
      expect([ ...mapIterable(input, (val): number => val + 3) ]).toEqual([ 4, 5, 6 ]);
    });
  });

  describe('#filterIterable', (): void => {
    it('filters the values of the iterable.', async(): Promise<void> => {
      const input = [ 1, 2, 3 ];
      expect([ ...filterIterable(input, (val): boolean => val % 2 === 1) ]).toEqual([ 1, 3 ]);
    });
  });

  describe('#concatIterables', (): void => {
    it('concatenates all the iterables.', async(): Promise<void> => {
      const input = [[ 1, 2, 3 ], [ 4, 5, 6 ], [ 7, 8, 9 ]];
      expect([ ...concatIterables(input) ]).toEqual([ 1, 2, 3, 4, 5, 6, 7, 8, 9 ]);
    });
  });

  describe('#reduceIterable', (): void => {
    it('reduces the values in an iterable.', async(): Promise<void> => {
      const input = [ 1, 2, 3 ];
      expect(reduceIterable(input, (acc, cur): number => acc + cur)).toBe(6);
    });

    it('can take a starting value.', async(): Promise<void> => {
      const input = [ 1, 2, 3 ];
      expect(reduceIterable(input, (acc, cur): number => acc + cur, 4)).toBe(10);
    });

    it('throws an error if the iterable is empty and there is no initial value.', async(): Promise<void> => {
      const input: number[] = [];
      expect((): number => reduceIterable(input, (acc, cur): number => acc + cur)).toThrow(TypeError);
    });
  });
});
