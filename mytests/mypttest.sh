
for i in [pt-grow-stack pt-big-stk-obj pt-grow-pusha pt-grow-stk-sc]:
do
  echo "Running $i"
  ./mygdbstart.sh $i --vm
done